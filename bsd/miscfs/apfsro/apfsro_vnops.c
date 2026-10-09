// SPDX-License-Identifier: MIT OR Apache-2.0

/*
 * apfsro vnode operations. See apfsro.h for the design.
 *
 * Every write-type operation fails with EROFS; the volume is immutable.
 */

#include <miscfs/apfsro/apfsro.h>
#include <kern/assert.h>
#include <kern/kalloc.h>
#include <libkern/libkern.h>
#include <sys/dirent.h>
#include <sys/errno.h>
#include <sys/mount_internal.h>
#include <sys/namei.h>
#include <sys/stat.h>
#include <sys/syslimits.h>
#include <sys/ubc.h>
#include <sys/uio_internal.h>
#include <sys/unistd.h>
#include <sys/vnode_internal.h>
#include <vfs/vfs_support.h>

#define VOPFUNC int (*)(void *)

int (**apfsro_vnodeop_p)(void *);

/* Every directory entry record is at least this large (4-byte aligned name). */
#define APFSRO_DIRSIZ(namlen) \
	((sizeof(struct dirent) - (MAXNAMLEN + 1)) + (((namlen) + 1 + 3) & ~3))

static uint8_t
apfsro_dtype(uint32_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFREG:
		return DT_REG;
	case S_IFDIR:
		return DT_DIR;
	case S_IFLNK:
		return DT_LNK;
	case S_IFCHR:
		return DT_CHR;
	case S_IFBLK:
		return DT_BLK;
	case S_IFIFO:
		return DT_FIFO;
	case S_IFSOCK:
		return DT_SOCK;
	default:
		return DT_UNKNOWN;
	}
}

/*
 * apfsro_lookup:
 *   Resolve the component in a_cnp inside directory a_dvp. The volume is
 *   read-only, so CREATE, DELETE and RENAME fail outright.
 */
static int
apfsro_lookup(struct vnop_lookup_args *ap)
{
	vnode_t dvp = ap->a_dvp;
	struct componentname *cnp = ap->a_cnp;
	mount_t mp = vnode_mount(dvp);
	struct apfsro_mount *am = VFSTOAPFSRO(mp);
	struct apfsro_node *dan = VTOAPFSRO(dvp);
	struct apfsro_attr attr;
	uint64_t parent;
	int error;

	if (cnp->cn_nameiop == DELETE || cnp->cn_nameiop == RENAME || cnp->cn_nameiop == CREATE) {
		return EROFS;
	}
	if (dvp->v_type != VDIR) {
		return ENOTDIR;
	}
	if (cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.') {
		error = vnode_get(dvp);
		if (error == 0) {
			*ap->a_vpp = dvp;
		}
		return error;
	}
	if ((cnp->cn_flags & ISDOTDOT) ||
	    (cnp->cn_namelen == 2 && cnp->cn_nameptr[0] == '.' && cnp->cn_nameptr[1] == '.')) {
		APFSRO_RUST_LOCK(am);
		error = xnu_rc_apfs_parent(am->am_handle, dan->an_attr.ino, &parent);
		APFSRO_RUST_UNLOCK(am);
		if (error) {
			return error;
		}
		return apfsro_vget_ino(mp, parent, NULL, NULLVP, NULL, ap->a_vpp);
	}

	APFSRO_RUST_LOCK(am);
	error = xnu_rc_apfs_lookup(am->am_handle, dan->an_attr.ino, cnp->cn_nameptr, cnp->cn_namelen, &attr);
	APFSRO_RUST_UNLOCK(am);
	if (error) {
		return error;
	}
	return apfsro_vget_ino(mp, attr.ino, &attr, dvp, cnp, ap->a_vpp);
}

/*
 * apfsro_getattr:
 *   Attributes were cached in the node when the vnode was created.
 */
static int
apfsro_getattr(struct vnop_getattr_args *ap)
{
	vnode_t vp = ap->a_vp;
	struct vnode_attr *vap = ap->a_vap;
	const struct apfsro_attr *a = &VTOAPFSRO(vp)->an_attr;
	int is_dir = (vp->v_type == VDIR);

	VATTR_RETURN(vap, va_type, vp->v_type);
	VATTR_RETURN(vap, va_mode, a->mode & ALLPERMS);
	VATTR_RETURN(vap, va_nlink, a->nlink);
	VATTR_RETURN(vap, va_uid, a->uid);
	VATTR_RETURN(vap, va_gid, a->gid);
	VATTR_RETURN(vap, va_fileid, a->ino);
	VATTR_RETURN(vap, va_linkid, a->ino);
	VATTR_RETURN(vap, va_flags, a->flags);
	VATTR_RETURN(vap, va_gen, 0);
	VATTR_RETURN(vap, va_rdev, 0);
	VATTR_RETURN(vap, va_iosize, 4096);
	VATTR_RETURN(vap, va_fsid, (uint32_t)vfs_statfs(vnode_mount(vp))->f_fsid.val[0]);
	VATTR_RETURN(vap, va_total_size, a->size);
	VATTR_RETURN(vap, va_total_alloc, a->alloc);
	VATTR_RETURN(vap, va_data_size, a->size);
	VATTR_RETURN(vap, va_data_alloc, a->alloc);
	if (is_dir) {
		VATTR_RETURN(vap, va_dirlinkcount, a->nlink);
		VATTR_RETURN(vap, va_nchildren, a->nlink > 2 ? a->nlink - 2 : 0);
	}
	if (VATTR_IS_ACTIVE(vap, va_access_time)) {
		vap->va_access_time.tv_sec = a->atime.sec;
		vap->va_access_time.tv_nsec = a->atime.nsec;
		VATTR_SET_SUPPORTED(vap, va_access_time);
	}
	if (VATTR_IS_ACTIVE(vap, va_modify_time)) {
		vap->va_modify_time.tv_sec = a->mtime.sec;
		vap->va_modify_time.tv_nsec = a->mtime.nsec;
		VATTR_SET_SUPPORTED(vap, va_modify_time);
	}
	if (VATTR_IS_ACTIVE(vap, va_change_time)) {
		vap->va_change_time.tv_sec = a->ctime.sec;
		vap->va_change_time.tv_nsec = a->ctime.nsec;
		VATTR_SET_SUPPORTED(vap, va_change_time);
	}
	if (VATTR_IS_ACTIVE(vap, va_create_time)) {
		vap->va_create_time.tv_sec = a->btime.sec;
		vap->va_create_time.tv_nsec = a->btime.nsec;
		VATTR_SET_SUPPORTED(vap, va_create_time);
	}
	return 0;
}

/*
 * apfsro_read:
 *   File data is served from the UBC, which pages it in through
 *   apfsro_pagein().
 */
static int
apfsro_read(struct vnop_read_args *ap)
{
	vnode_t vp = ap->a_vp;

	switch (vp->v_type) {
	case VREG:
		return cluster_read(vp, ap->a_uio, (off_t)VTOAPFSRO(vp)->an_attr.size, ap->a_ioflag);
	case VDIR:
		return EISDIR;
	default:
		return EINVAL;
	}
}

/*
 * apfsro_readdir:
 *   uio_offset is a position in the directory: 0 is ".", 1 is "..", and
 *   position N >= 2 is the Rust reader's entry at cookie N - 2. Entries are
 *   emitted as struct dirent records until the buffer is full.
 */
static int
apfsro_readdir(struct vnop_readdir_args *ap)
{
	vnode_t vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct apfsro_mount *am = VFSTOAPFSRO(vnode_mount(vp));
	const struct apfsro_attr *dattr = &VTOAPFSRO(vp)->an_attr;
	struct apfsro_dirent *de;
	struct dirent dirent;
	uint64_t pos, parent;
	int numdirent = 0, eof = 0, error = 0;

	if (ap->a_flags & (VNODE_READDIR_EXTENDED | VNODE_READDIR_REQSEEKOFF)) {
		return EINVAL;
	}
	if (vp->v_type != VDIR) {
		return ENOTDIR;
	}
	if (uio_offset(uio) < 0) {
		return EINVAL;
	}

	de = kalloc_type(struct apfsro_dirent, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	pos = (uint64_t)uio_offset(uio);

	while (uio_resid(uio) > 0) {
		const char *name;
		size_t namlen;

		bzero(&dirent, sizeof(dirent));
		if (pos < 2) {
			if (pos == 0) {
				dirent.d_ino = dattr->ino;
				name = ".";
			} else {
				APFSRO_RUST_LOCK(am);
				error = xnu_rc_apfs_parent(am->am_handle, dattr->ino, &parent);
				APFSRO_RUST_UNLOCK(am);
				if (error) {
					break;
				}
				dirent.d_ino = parent;
				name = "..";
			}
			namlen = pos + 1;
			dirent.d_type = DT_DIR;
		} else {
			APFSRO_RUST_LOCK(am);
			error = xnu_rc_apfs_readdir(am->am_handle, dattr->ino, pos - 2, de);
			APFSRO_RUST_UNLOCK(am);
			if (error) {
				break;
			}
			if (!de->valid) {
				eof = 1;
				break;
			}
			dirent.d_ino = de->ino;
			dirent.d_type = apfsro_dtype(de->mode);
			name = de->name;
			namlen = de->name_len;
		}
		dirent.d_namlen = (uint8_t)namlen;
		dirent.d_reclen = (uint16_t)APFSRO_DIRSIZ(namlen);
		if (uio_resid(uio) < dirent.d_reclen) {
			break;
		}
		bcopy(name, dirent.d_name, namlen);
		dirent.d_name[namlen] = '\0';
		error = uiomove((caddr_t)&dirent, dirent.d_reclen, uio);
		if (error) {
			break;
		}
		pos++;
		numdirent++;
	}

	kfree_type(struct apfsro_dirent, de);
	if (error == 0) {
		uio_setoffset(uio, (off_t)pos);
		if (ap->a_eofflag) {
			*ap->a_eofflag = eof;
		}
		if (ap->a_numdirent) {
			*ap->a_numdirent = numdirent;
		}
	}
	return error;
}

/*
 * apfsro_readlink:
 *   Copy the symlink target (embedded in the volume's metadata) out to the uio.
 */
static int
apfsro_readlink(struct vnop_readlink_args *ap)
{
	vnode_t vp = ap->a_vp;
	struct apfsro_mount *am = VFSTOAPFSRO(vnode_mount(vp));
	const struct apfsro_node *an = VTOAPFSRO(vp);
	size_t len = 0;
	char *buf;
	int error;

	if (vp->v_type != VLNK) {
		return EINVAL;
	}
	if (an->an_attr.size > MAXPATHLEN) {
		return ENAMETOOLONG;
	}
	buf = kalloc_data(MAXPATHLEN, Z_WAITOK);
	if (buf == NULL) {
		return ENOMEM;
	}
	APFSRO_RUST_LOCK(am);
	error = xnu_rc_apfs_readlink(am->am_handle, an->an_attr.ino, buf, MAXPATHLEN, &len);
	APFSRO_RUST_UNLOCK(am);
	if (error == 0) {
		error = uiomove(buf, (int)len, ap->a_uio);
	}
	kfree_data(buf, MAXPATHLEN);
	return error;
}

static int
apfsro_reclaim(struct vnop_reclaim_args *ap)
{
	apfsro_node_free(ap->a_vp);
	return 0;
}

/*
 * apfsro_open:
 *   The volume is read-only; opening for write is refused up front.
 */
static int
apfsro_open(struct vnop_open_args *ap)
{
	if (ap->a_mode & (FWRITE | O_TRUNC)) {
		return EROFS;
	}
	return 0;
}

/*
 * apfsro_pagein:
 *   cluster_pagein() maps the request to the ramdisk with apfsro_blockmap()
 *   and reads it through apfsro_strategy().
 */
static int
apfsro_pagein(struct vnop_pagein_args *ap)
{
	vnode_t vp = ap->a_vp;

	if (vp->v_type != VREG) {
		return EINVAL;
	}
	return cluster_pagein(vp, ap->a_pl, ap->a_pl_offset, ap->a_f_offset, ap->a_size,
	           (off_t)VTOAPFSRO(vp)->an_attr.size, ap->a_flags);
}

/*
 * apfsro_strategy:
 *   Pass the I/O (whose block numbers apfsro_blockmap() produced) down to the
 *   ramdisk device the volume is mounted from.
 */
static int
apfsro_strategy(struct vnop_strategy_args *ap)
{
	vnode_t devvp;
	int error;

	devvp = vfs_devvp(vnode_mount(buf_vnode(ap->a_bp)));
	if (devvp == NULLVP) {
		return EIO;
	}
	error = buf_strategy(devvp, ap);
	vnode_put(devvp);
	return error;
}

/*
 * apfsro_blockmap:
 *   Map a file offset to a block of the ramdisk using the file's APFS extents.
 *   A hole (or anything past the data) is reported as block -1, which the
 *   cluster layer zero-fills.
 */
static int
apfsro_blockmap(struct vnop_blockmap_args *ap)
{
	vnode_t vp = ap->a_vp;
	struct apfsro_mount *am = VFSTOAPFSRO(vnode_mount(vp));
	const struct apfsro_node *an = VTOAPFSRO(vp);
	uint32_t blksize = vnode_mount(vp)->mnt_devblocksize;
	struct apfsro_map map;
	int error;

	if (vp->v_type != VREG) {
		return ENOTSUP;
	}
	if (ap->a_foffset < 0) {
		return EINVAL;
	}

	APFSRO_RUST_LOCK(am);
	error = xnu_rc_apfs_map(am->am_handle, an->an_attr.ino, (uint64_t)ap->a_foffset, &map);
	APFSRO_RUST_UNLOCK(am);
	if (error) {
		return error;
	}

	if (ap->a_run) {
		*ap->a_run = (map.run > SIZE_MAX) ? SIZE_MAX : (size_t)map.run;
	}
	if (ap->a_poff) {
		*(int *)ap->a_poff = 0;
	}
	if (ap->a_bpn == NULL) {
		return 0;
	}
	if (map.phys == APFSRO_MAP_HOLE) {
		*ap->a_bpn = -1;
		return 0;
	}
	if (map.phys % blksize) {
		/* Callers pass page-aligned offsets, and extents are block-aligned. */
		if (ap->a_poff == NULL) {
			return EINVAL;
		}
		*(int *)ap->a_poff = (int)(map.phys % blksize);
	}
	*ap->a_bpn = (daddr64_t)(map.phys / blksize);
	return 0;
}

static int
apfsro_blktooff(struct vnop_blktooff_args *ap)
{
	*ap->a_offset = (off_t)ap->a_lblkno * vnode_mount(ap->a_vp)->mnt_devblocksize;
	return 0;
}

static int
apfsro_offtoblk(struct vnop_offtoblk_args *ap)
{
	*ap->a_lblkno = (daddr64_t)(ap->a_offset / vnode_mount(ap->a_vp)->mnt_devblocksize);
	return 0;
}

static int
apfsro_pathconf(struct vnop_pathconf_args *ap)
{
	struct apfsro_mount *am = VFSTOAPFSRO(vnode_mount(ap->a_vp));

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*ap->a_retval = LINK_MAX;
		return 0;
	case _PC_NAME_MAX:
		*ap->a_retval = APFSRO_NAME_MAX;
		return 0;
	case _PC_PATH_MAX:
		*ap->a_retval = PATH_MAX;
		return 0;
	case _PC_CHOWN_RESTRICTED:
	case _PC_NO_TRUNC:
	case _PC_CASE_PRESERVING:
		*ap->a_retval = 1;
		return 0;
	case _PC_CASE_SENSITIVE:
		*ap->a_retval = !am->am_case_insensitive;
		return 0;
	case _PC_FILESIZEBITS:
		*ap->a_retval = 64;
		return 0;
	case _PC_SYMLINK_MAX:
		*ap->a_retval = MAXPATHLEN;
		return 0;
	default:
		return EINVAL;
	}
}

/* Every operation that would modify the volume. */
static int
apfsro_erofs(__unused void *ap)
{
	return EROFS;
}

/*
 * Userspace probes the root with APFS-specific fsctls (dyld asks for the root
 * device status, for one) and accepts only "not a supported ioctl" for a
 * filesystem that doesn't implement them. None are implemented.
 */
static int
apfsro_ioctl(__unused void *ap)
{
	return ENOTTY;
}

const struct vnodeopv_entry_desc apfsro_vnodeop_entries[] = {
	{ .opve_op = &vnop_default_desc, .opve_impl = (VOPFUNC) vn_default_error },
	{ .opve_op = &vnop_lookup_desc, .opve_impl = (VOPFUNC) apfsro_lookup },
	{ .opve_op = &vnop_create_desc, .opve_impl = (VOPFUNC) apfsro_erofs },
	{ .opve_op = &vnop_mknod_desc, .opve_impl = (VOPFUNC) apfsro_erofs },
	{ .opve_op = &vnop_open_desc, .opve_impl = (VOPFUNC) apfsro_open },
	{ .opve_op = &vnop_close_desc, .opve_impl = (VOPFUNC) nop_close },
	{ .opve_op = &vnop_access_desc, .opve_impl = (VOPFUNC) nop_access },
	{ .opve_op = &vnop_getattr_desc, .opve_impl = (VOPFUNC) apfsro_getattr },
	{ .opve_op = &vnop_setattr_desc, .opve_impl = (VOPFUNC) apfsro_erofs },
	{ .opve_op = &vnop_read_desc, .opve_impl = (VOPFUNC) apfsro_read },
	{ .opve_op = &vnop_write_desc, .opve_impl = (VOPFUNC) apfsro_erofs },
	{ .opve_op = &vnop_ioctl_desc, .opve_impl = (VOPFUNC) apfsro_ioctl },
	{ .opve_op = &vnop_select_desc, .opve_impl = (VOPFUNC) err_select },
	{ .opve_op = &vnop_mmap_desc, .opve_impl = (VOPFUNC) nop_mmap },
	{ .opve_op = &vnop_fsync_desc, .opve_impl = (VOPFUNC) nop_fsync },
	{ .opve_op = &vnop_remove_desc, .opve_impl = (VOPFUNC) apfsro_erofs },
	{ .opve_op = &vnop_link_desc, .opve_impl = (VOPFUNC) apfsro_erofs },
	{ .opve_op = &vnop_rename_desc, .opve_impl = (VOPFUNC) apfsro_erofs },
	{ .opve_op = &vnop_mkdir_desc, .opve_impl = (VOPFUNC) apfsro_erofs },
	{ .opve_op = &vnop_rmdir_desc, .opve_impl = (VOPFUNC) apfsro_erofs },
	{ .opve_op = &vnop_symlink_desc, .opve_impl = (VOPFUNC) apfsro_erofs },
	{ .opve_op = &vnop_readdir_desc, .opve_impl = (VOPFUNC) apfsro_readdir },
	{ .opve_op = &vnop_readlink_desc, .opve_impl = (VOPFUNC) apfsro_readlink },
	{ .opve_op = &vnop_inactive_desc, .opve_impl = (VOPFUNC) nop_inactive },
	{ .opve_op = &vnop_reclaim_desc, .opve_impl = (VOPFUNC) apfsro_reclaim },
	{ .opve_op = &vnop_strategy_desc, .opve_impl = (VOPFUNC) apfsro_strategy },
	{ .opve_op = &vnop_pathconf_desc, .opve_impl = (VOPFUNC) apfsro_pathconf },
	{ .opve_op = &vnop_advlock_desc, .opve_impl = (VOPFUNC) err_advlock },
	{ .opve_op = &vnop_bwrite_desc, .opve_impl = (VOPFUNC) apfsro_erofs },
	{ .opve_op = &vnop_pagein_desc, .opve_impl = (VOPFUNC) apfsro_pagein },
	{ .opve_op = &vnop_pageout_desc, .opve_impl = (VOPFUNC) apfsro_erofs },
	{ .opve_op = &vnop_copyfile_desc, .opve_impl = (VOPFUNC) apfsro_erofs },
	{ .opve_op = &vnop_blktooff_desc, .opve_impl = (VOPFUNC) apfsro_blktooff },
	{ .opve_op = &vnop_offtoblk_desc, .opve_impl = (VOPFUNC) apfsro_offtoblk },
	{ .opve_op = &vnop_blockmap_desc, .opve_impl = (VOPFUNC) apfsro_blockmap },
	{ .opve_op = (struct vnodeop_desc *) NULL, .opve_impl = (VOPFUNC) NULL }
};

const struct vnodeopv_desc apfsro_vnodeop_opv_desc = {
	.opv_desc_vector_p = &apfsro_vnodeop_p,
	.opv_desc_ops = apfsro_vnodeop_entries
};
