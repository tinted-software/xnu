// SPDX-License-Identifier: MIT OR Apache-2.0

/*
 * apfsro VFS operations: mounting the root device's APFS container as the
 * read-only root filesystem.
 */

#include <miscfs/apfsro/apfsro.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <mach/thread_act.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <libkern/libkern.h>
#include <miscfs/specfs/specdev.h>
#include <sys/disk.h>
#include <sys/errno.h>
#include <sys/mount_internal.h>
#include <sys/uio.h>
#include <sys/vnode_internal.h>
#include <sys/sysctl.h>

LCK_GRP_DECLARE(apfsro_lck_grp, "apfsro");

static int apfsro_unmount(struct mount *mp, int mntflags, vfs_context_t ctx);
static int apfsro_root(mount_t mp, vnode_t *vpp, vfs_context_t ctx);
static int apfsro_vfs_getattr(mount_t mp, struct vfs_attr *fsap, vfs_context_t ctx);
static int apfsro_sync(struct mount *mp, int waitfor, vfs_context_t ctx);
static int apfsro_vget(mount_t mp, ino64_t ino, vnode_t *vpp, vfs_context_t ctx);
static int apfsro_init(struct vfsconf *vfsc);

/*
 * apfsro_io_read:
 *   One synchronous byte-range read through the (already opened) root device
 *   vnode. Runs on the I/O thread's own stack.
 */
static int
apfsro_io_read(struct apfsro_mount *am, uint64_t offset, void *buf, size_t len)
{
	vfs_context_t kctx = vfs_context_kernel();
	int resid = 0;
	int error;

	if (len > INT_MAX || offset > (uint64_t)INT64_MAX) {
		return EINVAL;
	}
	error = vn_rdwr(UIO_READ, am->am_devvp, (caddr_t)buf, (int)len, (off_t)offset,
	    UIO_SYSSPACE, IO_SYNC | IO_NODELOCKED, vfs_context_ucred(kctx), &resid,
	    vfs_context_proc(kctx));
	if (error == 0 && resid != 0) {
		error = EIO;
	}
	return error;
}

static void
apfsro_io_thread(void *arg, __unused wait_result_t wr)
{
	struct apfsro_mount *am = arg;

	lck_mtx_lock(&am->am_io_mtx);
	for (;;) {
		while (am->am_io_state == APFSRO_IO_IDLE || am->am_io_state == APFSRO_IO_DONE) {
			lck_mtx_sleep(&am->am_io_mtx, LCK_SLEEP_DEFAULT,
			    (event_t)&am->am_io_state, THREAD_UNINT);
		}
		if (am->am_io_state == APFSRO_IO_STOP) {
			break;
		}
		lck_mtx_unlock(&am->am_io_mtx);
		int error = apfsro_io_read(am, am->am_io_offset, am->am_io_buf, am->am_io_len);
		lck_mtx_lock(&am->am_io_mtx);
		am->am_io_error = error;
		am->am_io_state = APFSRO_IO_DONE;
		thread_wakeup((event_t)&am->am_io_state);
	}
	am->am_io_state = APFSRO_IO_STOPPED;
	thread_wakeup((event_t)&am->am_io_state);
	lck_mtx_unlock(&am->am_io_mtx);
	thread_terminate(current_thread());
	/* NOTREACHED */
}

/*
 * apfsro_dev_read:
 *   The Rust reader's view of the device. Posts the read to the I/O thread and
 *   sleeps until it completes; callers are serialized (am_rust_mtx, or the
 *   single mount thread), so there is at most one request.
 */
static int
apfsro_dev_read(void *ctx, uint64_t offset, void *buf, size_t len)
{
	struct apfsro_mount *am = ctx;
	int error;

	lck_mtx_lock(&am->am_io_mtx);
	am->am_io_offset = offset;
	am->am_io_buf = buf;
	am->am_io_len = len;
	am->am_io_state = APFSRO_IO_PENDING;
	thread_wakeup((event_t)&am->am_io_state);
	while (am->am_io_state != APFSRO_IO_DONE) {
		lck_mtx_sleep(&am->am_io_mtx, LCK_SLEEP_DEFAULT,
		    (event_t)&am->am_io_state, THREAD_UNINT);
	}
	error = am->am_io_error;
	am->am_io_state = APFSRO_IO_IDLE;
	lck_mtx_unlock(&am->am_io_mtx);
	return error;
}

static void
apfsro_io_stop(struct apfsro_mount *am)
{
	lck_mtx_lock(&am->am_io_mtx);
	am->am_io_state = APFSRO_IO_STOP;
	thread_wakeup((event_t)&am->am_io_state);
	while (am->am_io_state != APFSRO_IO_STOPPED) {
		lck_mtx_sleep(&am->am_io_mtx, LCK_SLEEP_DEFAULT,
		    (event_t)&am->am_io_state, THREAD_UNINT);
	}
	lck_mtx_unlock(&am->am_io_mtx);
	lck_mtx_destroy(&am->am_io_mtx, &apfsro_lck_grp);
}

/*
 * apfsro_mountroot:
 *   Given a mount (mp) and the vnode of the root device (rvp), mount the APFS
 *   container on that device. Any block device that reports a size qualifies;
 *   if the device holds no APFS container the mount fails (EINVAL for an
 *   unrecognized format) so another filesystem can claim it.
 *
 * Returns 0 on success, or an error.
 */
int
apfsro_mountroot(mount_t mp, vnode_t rvp, vfs_context_t ctx)
{
	struct apfsro_mount *am;
	struct apfsro_statfs sfs;
	uint64_t block_count = 0;
	uint32_t block_size = 0;
	uint64_t size;
	int error;

	if (VNOP_IOCTL(rvp, DKIOCGETBLOCKSIZE, (caddr_t)&block_size, 0, ctx) ||
	    VNOP_IOCTL(rvp, DKIOCGETBLOCKCOUNT, (caddr_t)&block_count, 0, ctx) ||
	    block_size == 0 || block_count == 0) {
		return EINVAL;
	}
	size = block_count * block_size;

	am = kalloc_type(struct apfsro_mount, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	am->am_devvp = rvp;
	lck_mtx_init(&am->am_rust_mtx, &apfsro_lck_grp, LCK_ATTR_NULL);
	lck_mtx_init(&am->am_hash_mtx, &apfsro_lck_grp, LCK_ATTR_NULL);
	lck_mtx_init(&am->am_io_mtx, &apfsro_lck_grp, LCK_ATTR_NULL);
	am->am_io_state = APFSRO_IO_IDLE;
	thread_t io_thread;
	if (kernel_thread_start(apfsro_io_thread, am, &io_thread) != KERN_SUCCESS) {
		lck_mtx_destroy(&am->am_io_mtx, &apfsro_lck_grp);
		lck_mtx_destroy(&am->am_hash_mtx, &apfsro_lck_grp);
		lck_mtx_destroy(&am->am_rust_mtx, &apfsro_lck_grp);
		kfree_type(struct apfsro_mount, am);
		return ENOMEM;
	}
	thread_deallocate(io_thread);
	for (unsigned int i = 0; i < APFSRO_HASH_SIZE; i++) {
		LIST_INIT(&am->am_hash[i]);
	}
	am->am_root_ino = xnu_rc_apfs_root_ino();

	error = xnu_rc_apfs_mount(apfsro_dev_read, am, size, &am->am_handle);
	if (error) {
		printf("apfsro_mountroot: no usable APFS volume on root device (%llu bytes): error %d\n",
		    size, error);
		goto fail;
	}

	error = xnu_rc_apfs_statfs(am->am_handle, &sfs);
	if (error) {
		xnu_rc_apfs_unmount(am->am_handle);
		goto fail;
	}
	am->am_case_insensitive = (sfs.flags & APFSRO_STATFS_CASE_INSENSITIVE) != 0;

	mp->mnt_data = (typeof(mp->mnt_data))am;
	mp->mnt_vfsstat.f_fsid.val[0] = (int32_t)rvp->v_rdev;
	mp->mnt_vfsstat.f_fsid.val[1] = (int32_t)mp->mnt_vtable->vfc_typenum;

	printf("apfsro_mountroot: mounted APFS volume from root device (%llu bytes)\n", size);
	return 0;

fail:
	apfsro_io_stop(am);
	lck_mtx_destroy(&am->am_hash_mtx, &apfsro_lck_grp);
	lck_mtx_destroy(&am->am_rust_mtx, &apfsro_lck_grp);
	kfree_type(struct apfsro_mount, am);
	return error;
}

/*
 * apfsro_unmount:
 *   Reclaim every vnode, then release the Rust reader. Root can only be
 *   unmounted forcibly (as a pivot away from it).
 */
static int
apfsro_unmount(struct mount *mp, int mntflags, __unused vfs_context_t ctx)
{
	struct apfsro_mount *am = VFSTOAPFSRO(mp);
	int error;

	error = vflush(mp, NULLVP, (mntflags & MNT_FORCE) ? FORCECLOSE : 0);
	if (error) {
		return error;
	}

	xnu_rc_apfs_unmount(am->am_handle);
	apfsro_io_stop(am);
	lck_mtx_destroy(&am->am_hash_mtx, &apfsro_lck_grp);
	lck_mtx_destroy(&am->am_rust_mtx, &apfsro_lck_grp);
	kfree_type(struct apfsro_mount, am);
	mp->mnt_data = NULL;
	return 0;
}

static int
apfsro_root(mount_t mp, vnode_t *vpp, __unused vfs_context_t ctx)
{
	return apfsro_vget_ino(mp, VFSTOAPFSRO(mp)->am_root_ino, NULL, NULLVP, NULL, vpp);
}

static int
apfsro_vget(mount_t mp, ino64_t ino, vnode_t *vpp, __unused vfs_context_t ctx)
{
	return apfsro_vget_ino(mp, (uint64_t)ino, NULL, NULLVP, NULL, vpp);
}

static int
apfsro_sync(__unused struct mount *mp, __unused int waitfor, __unused vfs_context_t ctx)
{
	return 0;
}

/*
 * apfsro_vfs_getattr:
 *   Volume attributes, from the Rust reader's view of the container.
 */
static int
apfsro_vfs_getattr(mount_t mp, struct vfs_attr *fsap, __unused vfs_context_t ctx)
{
	struct apfsro_mount *am = VFSTOAPFSRO(mp);
	struct apfsro_statfs sfs;
	int error;

	APFSRO_RUST_LOCK(am);
	error = xnu_rc_apfs_statfs(am->am_handle, &sfs);
	APFSRO_RUST_UNLOCK(am);
	if (error) {
		return error;
	}

	VFSATTR_RETURN(fsap, f_objcount, sfs.files);
	VFSATTR_RETURN(fsap, f_maxobjcount, sfs.files);
	VFSATTR_RETURN(fsap, f_bsize, sfs.block_size);
	VFSATTR_RETURN(fsap, f_iosize, sfs.block_size);
	VFSATTR_RETURN(fsap, f_blocks, sfs.blocks);
	VFSATTR_RETURN(fsap, f_bfree, sfs.bfree);
	VFSATTR_RETURN(fsap, f_bavail, sfs.bfree);
	VFSATTR_RETURN(fsap, f_bused, sfs.blocks - sfs.bfree);
	VFSATTR_RETURN(fsap, f_files, sfs.files);
	VFSATTR_RETURN(fsap, f_ffree, 0);
	VFSATTR_RETURN(fsap, f_fssubtype, 0);

	if (VFSATTR_IS_ACTIVE(fsap, f_capabilities)) {
		vol_capabilities_attr_t *cap = &fsap->f_capabilities;
		uint32_t format = VOL_CAP_FMT_SYMBOLICLINKS | VOL_CAP_FMT_HARDLINKS |
		    VOL_CAP_FMT_CASE_PRESERVING | VOL_CAP_FMT_FAST_STATFS |
		    VOL_CAP_FMT_2TB_FILESIZE | VOL_CAP_FMT_HIDDEN_FILES;

		if (!am->am_case_insensitive) {
			format |= VOL_CAP_FMT_CASE_SENSITIVE;
		}
		cap->capabilities[VOL_CAPABILITIES_FORMAT] = format;
		cap->capabilities[VOL_CAPABILITIES_INTERFACES] = 0;
		cap->capabilities[VOL_CAPABILITIES_RESERVED1] = 0;
		cap->capabilities[VOL_CAPABILITIES_RESERVED2] = 0;
		cap->valid[VOL_CAPABILITIES_FORMAT] = format | VOL_CAP_FMT_CASE_SENSITIVE;
		cap->valid[VOL_CAPABILITIES_INTERFACES] = 0;
		cap->valid[VOL_CAPABILITIES_RESERVED1] = 0;
		cap->valid[VOL_CAPABILITIES_RESERVED2] = 0;
		VFSATTR_SET_SUPPORTED(fsap, f_capabilities);
	}
	return 0;
}

static int
apfsro_init(__unused struct vfsconf *vfsc)
{
	return 0;
}

/*
 * The root is mounted by apfsro_mountroot(). mount(2) can only update an
 * existing mount (mount -u, as `mount -P 1` does to apply options such as
 * nosuid): the generic code applies the flag changes, we only veto a
 * read-write upgrade. Mounting any other volume is not supported yet.
 */
static int
apfsro_mount(mount_t mp, __unused vnode_t devvp, __unused user_addr_t data, __unused vfs_context_t ctx)
{
	if ((vfs_flags(mp) & MNT_UPDATE) == 0) {
		return ENOTSUP;
	}
	if (mp->mnt_kern_flag & MNTK_WANTRDWR) {
		return EROFS;
	}
	return 0;
}

const struct vfsops apfsro_vfsops = {
	.vfs_mount = apfsro_mount,
	.vfs_unmount = apfsro_unmount,
	.vfs_root = apfsro_root,
	.vfs_getattr = apfsro_vfs_getattr,
	.vfs_sync = apfsro_sync,
	.vfs_vget = apfsro_vget,
	.vfs_init = apfsro_init,
};

/*
 * sysctl vfs.generic.apfs.edt_fstab:
 *
 * On APFS root, libsystem_info's getfsent() exclusively queries this sysctl
 * to retrieve fstab entries (refusing to read /etc/fstab). We serve the
 * /private/var tmpfs mount entry here so mount -P 1 and mount -P 2 mount it.
 */
struct edt_fstab {
	char     fs_spec[32];
	char     fs_file[64];
	char     fs_vfstype[32];
	char     fs_mntops[64];
	char     fs_type[32];
	uint32_t fs_freq;
	uint32_t fs_passno;
	uint32_t fs_pad;
};

static int
sysctl_apfs_edt_fstab(__unused struct sysctl_oid *oidp, __unused void *arg1,
    __unused int arg2, struct sysctl_req *req)
{
	static const struct edt_fstab entries[] = {
		{
			.fs_spec = "tmpfs",
			.fs_file = "/private/var",
			.fs_vfstype = "tmpfs",
			.fs_mntops = "rw",
			.fs_type = "rw",
			.fs_freq = 0,
			.fs_passno = 1,
			.fs_pad = 0,
		},
	};
	return SYSCTL_OUT(req, entries, sizeof(entries));
}

SYSCTL_DECL(_vfs_generic);
SYSCTL_NODE(_vfs_generic, OID_AUTO, apfs, CTLFLAG_RW | CTLFLAG_LOCKED, NULL, "apfs hinge");
SYSCTL_PROC(_vfs_generic_apfs, OID_AUTO, edt_fstab,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    NULL, 0, sysctl_apfs_edt_fstab, "S,edt_fstab", "Embedded device tree fstab");
