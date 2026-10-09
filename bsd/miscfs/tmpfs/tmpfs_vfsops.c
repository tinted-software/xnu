// SPDX-License-Identifier: GPL-2.0
#include <miscfs/tmpfs/tmpfs.h>
#include <sys/vnode_internal.h>
#include <sys/mount_internal.h>
#include <sys/errno.h>

LCK_GRP_DECLARE(tmpfs_lck_grp, "tmpfs");

static int
tmpfs_vfs_mount(mount_t mp, __unused vnode_t devvp, user_addr_t data, vfs_context_t ctx)
{
	struct tmpfs_mount *tm;
	struct tmpfs_args args;
	int error;

	if (vfs_flags(mp) & MNT_UPDATE) {
		return 0;
	}

	bzero(&args, sizeof(args));
	if (data != USER_ADDR_NULL) {
		error = copyin(data, &args, sizeof(args));
		if (error != 0) {
			return error;
		}
	}

	tm = kalloc_type(struct tmpfs_mount, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	tm->tm_mp = mp;
	lck_mtx_init(&tm->tm_lock, &tmpfs_lck_grp, LCK_ATTR_NULL);
	tm->tm_next_ino = 3;
	tm->tm_max_pages = args.ta_max_pages ? args.ta_max_pages : TMPFS_DEFAULT_MAX_PAGES;
	tm->tm_max_nodes = args.ta_max_nodes ? args.ta_max_nodes : TMPFS_DEFAULT_MAX_NODES;
	tm->tm_case_sensitive = (args.ta_case_sensitive != 0);
	LIST_INIT(&tm->tm_nodes);

	/* Create root directory node (ino 2) */
	error = tmpfs_alloc_node(tm, VDIR, 0755, kauth_cred_getuid(vfs_context_ucred(ctx)),
	    kauth_cred_getgid(vfs_context_ucred(ctx)), TMPFS_ROOT_INO, &tm->tm_root);
	if (error != 0) {
		lck_mtx_destroy(&tm->tm_lock, &tmpfs_lck_grp);
		kfree_type(struct tmpfs_mount, tm);
		return error;
	}
	tm->tm_root->dir.tn_parent_ino = TMPFS_ROOT_INO;
	tm->tm_root->tn_nlink = 2;

	/* Pre-populate standard /var directories needed by boot tasks */
	struct tmpfs_node *db_node = NULL, *log_node = NULL;
	if (tmpfs_alloc_node(tm, VDIR, 0755, 0, 0, 0, &db_node) == 0) {
		db_node->dir.tn_parent_ino = TMPFS_ROOT_INO;
		tmpfs_dir_add_entry(tm->tm_root, "db", 2, db_node->tn_ino);
		tm->tm_root->tn_nlink++;
		struct tmpfs_node *tz_node = NULL;
		if (tmpfs_alloc_node(tm, VDIR, 0755, 0, 0, 0, &tz_node) == 0) {
			tz_node->dir.tn_parent_ino = db_node->tn_ino;
			tmpfs_dir_add_entry(db_node, "timezone", 8, tz_node->tn_ino);
			db_node->tn_nlink++;
			struct tmpfs_node *sub_tz = NULL;
			if (tmpfs_alloc_node(tm, VDIR, 0755, 0, 0, 0, &sub_tz) == 0) {
				sub_tz->dir.tn_parent_ino = tz_node->tn_ino;
				tmpfs_dir_add_entry(tz_node, "tz", 2, sub_tz->tn_ino);
				tz_node->tn_nlink++;
			}
		}
	}
	if (tmpfs_alloc_node(tm, VDIR, 0755, 0, 0, 0, &log_node) == 0) {
		log_node->dir.tn_parent_ino = TMPFS_ROOT_INO;
		tmpfs_dir_add_entry(tm->tm_root, "log", 3, log_node->tn_ino);
		tm->tm_root->tn_nlink++;
		struct tmpfs_node *launchd_log = NULL;
		if (tmpfs_alloc_node(tm, VDIR, 0755, 0, 0, 0, &launchd_log) == 0) {
			launchd_log->dir.tn_parent_ino = log_node->tn_ino;
			tmpfs_dir_add_entry(log_node, "com.apple.xpc.launchd", 21, launchd_log->tn_ino);
			log_node->tn_nlink++;
		}
	}
	struct tmpfs_node *sub = NULL;
	if (tmpfs_alloc_node(tm, VDIR, 0755, 0, 0, 0, &sub) == 0) {
		sub->dir.tn_parent_ino = TMPFS_ROOT_INO;
		tmpfs_dir_add_entry(tm->tm_root, "run", 3, sub->tn_ino);
		tm->tm_root->tn_nlink++;
	}
	if (tmpfs_alloc_node(tm, VDIR, 01777, 0, 0, 0, &sub) == 0) {
		sub->dir.tn_parent_ino = TMPFS_ROOT_INO;
		tmpfs_dir_add_entry(tm->tm_root, "tmp", 3, sub->tn_ino);
		tm->tm_root->tn_nlink++;
	}
	if (tmpfs_alloc_node(tm, VDIR, 0755, 0, 0, 0, &sub) == 0) {
		sub->dir.tn_parent_ino = TMPFS_ROOT_INO;
		tmpfs_dir_add_entry(tm->tm_root, "mobile", 6, sub->tn_ino);
		tm->tm_root->tn_nlink++;
	}
	if (tmpfs_alloc_node(tm, VDIR, 0755, 0, 0, 0, &sub) == 0) {
		sub->dir.tn_parent_ino = TMPFS_ROOT_INO;
		tmpfs_dir_add_entry(tm->tm_root, "folders", 7, sub->tn_ino);
		tm->tm_root->tn_nlink++;
	}
	if (tmpfs_alloc_node(tm, VDIR, 0755, 0, 0, 0, &sub) == 0) {
		sub->dir.tn_parent_ino = TMPFS_ROOT_INO;
		tmpfs_dir_add_entry(tm->tm_root, "preferences", 11, sub->tn_ino);
		tm->tm_root->tn_nlink++;
	}

	vfs_setfsprivate(mp, tm);
	vfs_setlocklocal(mp);
	vfs_getnewfsid(mp);

	mp->mnt_vfsstat.f_fsid.val[0] = (int32_t)VM_KERNEL_ADDRHASH(tm);
	mp->mnt_vfsstat.f_fsid.val[1] = vfs_typenum(mp);
	mp->mnt_flag |= MNT_LOCAL;

	return 0;
}

static int
tmpfs_vfs_unmount(mount_t mp, int mntflags, __unused vfs_context_t ctx)
{
	struct tmpfs_mount *tm = VFSTOTMPFS(mp);
	struct tmpfs_node *tn, *ttn;
	int error;

	error = vflush(mp, NULLVP, mntflags);
	if (error != 0) {
		return error;
	}

	TMPFS_LOCK(tm);
	vfs_setfsprivate(mp, NULL);

	LIST_FOREACH_SAFE(tn, &tm->tm_nodes, tn_entries, ttn) {
		tmpfs_free_node(tn);
	}

	TMPFS_UNLOCK(tm);
	lck_mtx_destroy(&tm->tm_lock, &tmpfs_lck_grp);
	kfree_type(struct tmpfs_mount, tm);
	return 0;
}

static int
tmpfs_vfs_root(mount_t mp, vnode_t *vpp, __unused vfs_context_t ctx)
{
	struct tmpfs_mount *tm = VFSTOTMPFS(mp);
	int error;

	TMPFS_LOCK(tm);
	error = tmpfs_vget_node(mp, tm->tm_root, NULLVP, NULL, vpp);
	TMPFS_UNLOCK(tm);
	return error;
}

static int
tmpfs_vfs_getattr(mount_t mp, struct vfs_attr *fsap, __unused vfs_context_t ctx)
{
	struct tmpfs_mount *tm = VFSTOTMPFS(mp);

	TMPFS_LOCK(tm);
	VFSATTR_RETURN(fsap, f_bsize, TMPFS_PAGE_SIZE);
	VFSATTR_RETURN(fsap, f_iosize, TMPFS_PAGE_SIZE);
	VFSATTR_RETURN(fsap, f_blocks, tm->tm_max_pages);
	VFSATTR_RETURN(fsap, f_bused, tm->tm_pages_used);
	VFSATTR_RETURN(fsap, f_bfree, tm->tm_max_pages > tm->tm_pages_used ? tm->tm_max_pages - tm->tm_pages_used : 0);
	VFSATTR_RETURN(fsap, f_bavail, tm->tm_max_pages > tm->tm_pages_used ? tm->tm_max_pages - tm->tm_pages_used : 0);
	VFSATTR_RETURN(fsap, f_files, tm->tm_max_nodes);
	VFSATTR_RETURN(fsap, f_ffree, tm->tm_max_nodes > tm->tm_nodes_used ? tm->tm_max_nodes - tm->tm_nodes_used : 0);
	VFSATTR_RETURN(fsap, f_objcount, tm->tm_nodes_used);
	VFSATTR_RETURN(fsap, f_filecount, tm->tm_nodes_used);
	VFSATTR_RETURN(fsap, f_maxobjcount, tm->tm_max_nodes);

	if (VFSATTR_IS_ACTIVE(fsap, f_capabilities)) {
		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_FORMAT] =
		    VOL_CAP_FMT_SYMBOLICLINKS |
		    VOL_CAP_FMT_HARDLINKS |
		    VOL_CAP_FMT_CASE_PRESERVING |
		    (tm->tm_case_sensitive ? VOL_CAP_FMT_CASE_SENSITIVE : 0);
		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_INTERFACES] =
		    VOL_CAP_INT_ATTRLIST;
		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_RESERVED1] = 0;
		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_RESERVED2] = 0;

		fsap->f_capabilities.valid[VOL_CAPABILITIES_FORMAT] =
		    VOL_CAP_FMT_SYMBOLICLINKS |
		    VOL_CAP_FMT_HARDLINKS |
		    VOL_CAP_FMT_CASE_SENSITIVE |
		    VOL_CAP_FMT_CASE_PRESERVING;
		fsap->f_capabilities.valid[VOL_CAPABILITIES_INTERFACES] =
		    VOL_CAP_INT_ATTRLIST;
		VFSATTR_SET_SUPPORTED(fsap, f_capabilities);
	}
	TMPFS_UNLOCK(tm);
	return 0;
}

static int
tmpfs_vfs_sync(__unused mount_t mp, __unused int waitfor, __unused vfs_context_t ctx)
{
	return 0;
}

static int
tmpfs_vfs_vget(mount_t mp, ino64_t ino, vnode_t *vpp, __unused vfs_context_t ctx)
{
	struct tmpfs_mount *tm = VFSTOTMPFS(mp);
	struct tmpfs_node *tn;
	int error = ENOENT;

	TMPFS_LOCK(tm);
	LIST_FOREACH(tn, &tm->tm_nodes, tn_entries) {
		if (tn->tn_ino == ino) {
			error = tmpfs_vget_node(mp, tn, NULLVP, NULL, vpp);
			break;
		}
	}
	TMPFS_UNLOCK(tm);
	return error;
}

static int
tmpfs_vfs_init(__unused struct vfsconf *vfsc)
{
	return 0;
}

const struct vfsops tmpfs_vfsops = {
	.vfs_mount = tmpfs_vfs_mount,
	.vfs_unmount = tmpfs_vfs_unmount,
	.vfs_root = tmpfs_vfs_root,
	.vfs_getattr = tmpfs_vfs_getattr,
	.vfs_sync = tmpfs_vfs_sync,
	.vfs_vget = tmpfs_vfs_vget,
	.vfs_init = tmpfs_vfs_init,
};
