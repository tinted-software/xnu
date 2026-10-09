// SPDX-License-Identifier: GPL-2.0
#include <miscfs/tmpfs/tmpfs.h>
#include <sys/dirent.h>
#include <sys/errno.h>
#include <sys/mount_internal.h>
#include <sys/namei.h>
#include <sys/stat.h>
#include <sys/syslimits.h>
#include <sys/ubc.h>
#include <sys/ubc_internal.h>
#include <sys/uio_internal.h>
#include <sys/vnode_internal.h>
#include <vfs/vfs_support.h>

int (**tmpfs_vnodeop_p)(void *);
#define VOPFUNC int (*)(void *)
static const char tmpfs_zeros[512] = {0};

#define TMPFS_DIRSIZ(namlen) \
	((sizeof(struct dirent) - (sizeof(((struct dirent *)0)->d_name))) + (((namlen) + 1 + 3) & ~3))

static inline uint8_t
tmpfs_vtype_to_dtype(enum vtype vt)
{
	switch (vt) {
	case VDIR:  return DT_DIR;
	case VREG:  return DT_REG;
	case VLNK:  return DT_LNK;
	case VFIFO: return DT_FIFO;
	case VCHR:  return DT_CHR;
	case VBLK:  return DT_BLK;
	case VSOCK: return DT_SOCK;
	default:    return DT_UNKNOWN;
	}
}

static int
tmpfs_lookup(struct vnop_lookup_args *ap)
{
	vnode_t dvp = ap->a_dvp;
	vnode_t *vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	struct tmpfs_mount *tm = VFSTOTMPFS(vnode_mount(dvp));
	struct tmpfs_node *dnode = VTOTMPFS(dvp);
	struct tmpfs_node *target_node = NULL;
	struct tmpfs_dirent *de;
	int error = 0;

	*vpp = NULLVP;

	if (dvp->v_type != VDIR) {
		return ENOTDIR;
	}

	TMPFS_LOCK(tm);

	if (cnp->cn_namelen == 1 && cnp->cn_nameptr[0] == '.') {
		TMPFS_UNLOCK(tm);
		error = vnode_get(dvp);
		if (error == 0) {
			*vpp = dvp;
		}
		return error;
	}

	if ((cnp->cn_flags & ISDOTDOT) ||
	    (cnp->cn_namelen == 2 && cnp->cn_nameptr[0] == '.' && cnp->cn_nameptr[1] == '.')) {
		uint64_t parent_ino = dnode->dir.tn_parent_ino;
		struct tmpfs_node *pnode;
		LIST_FOREACH(pnode, &tm->tm_nodes, tn_entries) {
			if (pnode->tn_ino == parent_ino) {
				target_node = pnode;
				break;
			}
		}
		if (target_node == NULL) {
			TMPFS_UNLOCK(tm);
			return ENOENT;
		}
		error = tmpfs_vget_node(vnode_mount(dvp), target_node, NULLVP, cnp, vpp);
		TMPFS_UNLOCK(tm);
		return error;
	}

	de = tmpfs_dir_lookup(dnode, cnp->cn_nameptr, cnp->cn_namelen, tm->tm_case_sensitive);
	if (de != NULL) {
		struct tmpfs_node *tn;
		LIST_FOREACH(tn, &tm->tm_nodes, tn_entries) {
			if (tn->tn_ino == de->td_ino) {
				target_node = tn;
				break;
			}
		}
	}

	if (target_node == NULL) {
		TMPFS_UNLOCK(tm);
		if ((cnp->cn_nameiop == CREATE || cnp->cn_nameiop == RENAME) &&
		    (cnp->cn_flags & ISLASTCN)) {
			return EJUSTRETURN;
		}
		return ENOENT;
	}

	error = tmpfs_vget_node(vnode_mount(dvp), target_node, dvp, cnp, vpp);
	TMPFS_UNLOCK(tm);
	return error;
}

static int
tmpfs_create(struct vnop_create_args *ap)
{
	vnode_t dvp = ap->a_dvp;
	vnode_t *vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	struct vnode_attr *vap = ap->a_vap;
	struct tmpfs_mount *tm = VFSTOTMPFS(vnode_mount(dvp));
	struct tmpfs_node *dnode = VTOTMPFS(dvp);
	struct tmpfs_node *tn = NULL;
	int error;

	*vpp = NULLVP;
	if (dvp->v_type != VDIR) {
		return ENOTDIR;
	}

	TMPFS_LOCK(tm);

	if (tmpfs_dir_lookup(dnode, cnp->cn_nameptr, cnp->cn_namelen, tm->tm_case_sensitive) != NULL) {
		TMPFS_UNLOCK(tm);
		return EEXIST;
	}

	mode_t mode = (vap->va_mode & ALLPERMS);
	uid_t uid = VATTR_IS_ACTIVE(vap, va_uid) ? vap->va_uid : kauth_cred_getuid(vfs_context_ucred(ap->a_context));
	gid_t gid = VATTR_IS_ACTIVE(vap, va_gid) ? vap->va_gid : dnode->tn_gid;

	error = tmpfs_alloc_node(tm, VREG, mode, uid, gid, 0, &tn);
	if (error != 0) {
		TMPFS_UNLOCK(tm);
		return error;
	}

	error = tmpfs_dir_add_entry(dnode, cnp->cn_nameptr, cnp->cn_namelen, tn->tn_ino);
	if (error != 0) {
		tmpfs_free_node(tn);
		TMPFS_UNLOCK(tm);
		return error;
	}

	error = tmpfs_vget_node(vnode_mount(dvp), tn, dvp, cnp, vpp);
	TMPFS_UNLOCK(tm);
	return error;
}

static int
tmpfs_open(struct vnop_open_args *ap)
{
	return 0;
}

static int
tmpfs_getattr(struct vnop_getattr_args *ap)
{
	vnode_t vp = ap->a_vp;
	struct vnode_attr *vap = ap->a_vap;
	struct tmpfs_mount *tm = VFSTOTMPFS(vnode_mount(vp));
	struct tmpfs_node *tn = VTOTMPFS(vp);

	TMPFS_LOCK(tm);

	VATTR_RETURN(vap, va_type, tn->tn_type);
	VATTR_RETURN(vap, va_mode, tn->tn_mode & ALLPERMS);
	VATTR_RETURN(vap, va_nlink, tn->tn_nlink);
	VATTR_RETURN(vap, va_uid, tn->tn_uid);
	VATTR_RETURN(vap, va_gid, tn->tn_gid);
	VATTR_RETURN(vap, va_fsid, vnode_mount(vp)->mnt_vfsstat.f_fsid.val[0]);
	VATTR_RETURN(vap, va_fileid, tn->tn_ino);

	off_t size = 0;
	if (tn->tn_type == VREG) {
		size = tn->reg.tn_size;
	} else if (tn->tn_type == VDIR) {
		size = (off_t)tn->dir.tn_num_entries * sizeof(struct dirent);
	} else if (tn->tn_type == VLNK) {
		size = (off_t)tn->link.tn_target_len;
	}

	VATTR_RETURN(vap, va_data_size, size);
	VATTR_RETURN(vap, va_total_alloc, (size + TMPFS_PAGE_SIZE - 1) & ~(TMPFS_PAGE_SIZE - 1));

	if (VATTR_IS_ACTIVE(vap, va_access_time)) {
		vap->va_access_time = tn->tn_atime;
		VATTR_SET_SUPPORTED(vap, va_access_time);
	}
	if (VATTR_IS_ACTIVE(vap, va_modify_time)) {
		vap->va_modify_time = tn->tn_mtime;
		VATTR_SET_SUPPORTED(vap, va_modify_time);
	}
	if (VATTR_IS_ACTIVE(vap, va_change_time)) {
		vap->va_change_time = tn->tn_ctime;
		VATTR_SET_SUPPORTED(vap, va_change_time);
	}
	if (VATTR_IS_ACTIVE(vap, va_create_time)) {
		vap->va_create_time = tn->tn_btime;
		VATTR_SET_SUPPORTED(vap, va_create_time);
	}

	TMPFS_UNLOCK(tm);
	return 0;
}

static int
tmpfs_setattr(struct vnop_setattr_args *ap)
{
	vnode_t vp = ap->a_vp;
	struct vnode_attr *vap = ap->a_vap;
	struct tmpfs_mount *tm = VFSTOTMPFS(vnode_mount(vp));
	struct tmpfs_node *tn = VTOTMPFS(vp);

	TMPFS_LOCK(tm);

	if (VATTR_IS_ACTIVE(vap, va_mode)) {
		tn->tn_mode = vap->va_mode;
	}
	if (VATTR_IS_ACTIVE(vap, va_uid)) {
		tn->tn_uid = vap->va_uid;
	}
	if (VATTR_IS_ACTIVE(vap, va_gid)) {
		tn->tn_gid = vap->va_gid;
	}
	if (VATTR_IS_ACTIVE(vap, va_data_size) && tn->tn_type == VREG) {
		if (vap->va_data_size < (uint64_t)tn->reg.tn_size) {
			tmpfs_truncate_file(tn, (off_t)vap->va_data_size);
		} else if (vap->va_data_size > (uint64_t)tn->reg.tn_size) {
			tmpfs_grow_file(tn, (off_t)vap->va_data_size);
		}
		ubc_setsize(vp, tn->reg.tn_size);
	}
	if (VATTR_IS_ACTIVE(vap, va_access_time)) {
		tn->tn_atime = vap->va_access_time;
	}
	if (VATTR_IS_ACTIVE(vap, va_modify_time)) {
		tn->tn_mtime = vap->va_modify_time;
	}
	if (VATTR_IS_ACTIVE(vap, va_change_time)) {
		tn->tn_ctime = vap->va_change_time;
	}
	nanotime(&tn->tn_ctime);

	TMPFS_UNLOCK(tm);
	return 0;
}

static int
tmpfs_read(struct vnop_read_args *ap)
{
	vnode_t vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct tmpfs_mount *tm = VFSTOTMPFS(vnode_mount(vp));
	struct tmpfs_node *tn = VTOTMPFS(vp);
	int error = 0;

	if (vp->v_type == VDIR) {
		return EISDIR;
	}
	if (vp->v_type != VREG) {
		return EINVAL;
	}

	TMPFS_LOCK(tm);
	off_t offset = uio_offset(uio);
	if (offset < 0 || offset >= tn->reg.tn_size) {
		TMPFS_UNLOCK(tm);
		return 0;
	}
	user_ssize_t resid = uio_resid(uio);
	if (offset + resid > tn->reg.tn_size) {
		resid = (user_ssize_t)(tn->reg.tn_size - offset);
	}

	while (resid > 0) {
		size_t pindex = (size_t)(offset / TMPFS_PAGE_SIZE);
		size_t poff = (size_t)(offset % TMPFS_PAGE_SIZE);
		size_t to_copy = TMPFS_PAGE_SIZE - poff;
		if (to_copy > (size_t)resid) {
			to_copy = (size_t)resid;
		}

		void *page = (pindex < tn->reg.tn_npages) ? tn->reg.tn_pages[pindex] : NULL;
		TMPFS_UNLOCK(tm);

		if (page != NULL) {
			error = uiomove((char *)page + poff, (int)to_copy, uio);
		} else {
			size_t rem = to_copy;
			while (rem > 0) {
				int chunk = rem > sizeof(tmpfs_zeros) ? (int)sizeof(tmpfs_zeros) : (int)rem;
				error = uiomove(tmpfs_zeros, chunk, uio);
				if (error != 0) {
					break;
				}
				rem -= (size_t)chunk;
			}
		}

		TMPFS_LOCK(tm);
		if (error != 0) {
			break;
		}
		offset += to_copy;
		resid -= to_copy;
	}
	nanotime(&tn->tn_atime);
	TMPFS_UNLOCK(tm);
	return error;
}

static int
tmpfs_write(struct vnop_write_args *ap)
{
	vnode_t vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct tmpfs_mount *tm = VFSTOTMPFS(vnode_mount(vp));
	struct tmpfs_node *tn = VTOTMPFS(vp);
	int error = 0;

	if (vp->v_type == VDIR) {
		return EISDIR;
	}
	if (vp->v_type != VREG) {
		return EINVAL;
	}

	TMPFS_LOCK(tm);
	off_t offset = uio_offset(uio);
	if (ap->a_ioflag & IO_APPEND) {
		offset = tn->reg.tn_size;
	}
	if (offset < 0) {
		TMPFS_UNLOCK(tm);
		return EINVAL;
	}

	user_ssize_t resid = uio_resid(uio);
	off_t end_offset = offset + resid;
	if (end_offset > tn->reg.tn_size) {
		error = tmpfs_grow_file(tn, end_offset);
		if (error != 0) {
			TMPFS_UNLOCK(tm);
			return error;
		}
	}

	while (resid > 0) {
		size_t pindex = (size_t)(offset / TMPFS_PAGE_SIZE);
		size_t poff = (size_t)(offset % TMPFS_PAGE_SIZE);
		size_t to_copy = TMPFS_PAGE_SIZE - poff;
		if (to_copy > (size_t)resid) {
			to_copy = (size_t)resid;
		}

		if (pindex >= tn->reg.tn_npages || tn->reg.tn_pages[pindex] == NULL) {
			if (tm->tm_pages_used >= tm->tm_max_pages) {
				error = ENOSPC;
				break;
			}
			void *pg = kalloc_data(TMPFS_PAGE_SIZE, Z_WAITOK | Z_ZERO);
			if (pg == NULL) {
				error = ENOSPC;
				break;
			}
			tn->reg.tn_pages[pindex] = pg;
			tm->tm_pages_used++;
		}
		void *page = tn->reg.tn_pages[pindex];
		TMPFS_UNLOCK(tm);

		error = uiomove((char *)page + poff, (int)to_copy, uio);

		TMPFS_LOCK(tm);
		if (error != 0) {
			break;
		}
		offset += to_copy;
		resid -= to_copy;
	}

	if (offset > tn->reg.tn_size) {
		tn->reg.tn_size = offset;
	}
	ubc_setsize(vp, tn->reg.tn_size);
	nanotime(&tn->tn_mtime);
	tn->tn_ctime = tn->tn_mtime;

	TMPFS_UNLOCK(tm);
	return error;
}

static int
tmpfs_remove(struct vnop_remove_args *ap)
{
	vnode_t dvp = ap->a_dvp;
	vnode_t vp = ap->a_vp;
	struct componentname *cnp = ap->a_cnp;
	struct tmpfs_mount *tm = VFSTOTMPFS(vnode_mount(dvp));
	struct tmpfs_node *dnode = VTOTMPFS(dvp);
	struct tmpfs_node *tn = VTOTMPFS(vp);
	int error;

	TMPFS_LOCK(tm);
	error = tmpfs_dir_remove_entry(dnode, cnp->cn_nameptr, cnp->cn_namelen, tm->tm_case_sensitive);
	if (error == 0) {
		if (tn->tn_nlink > 0) {
			tn->tn_nlink--;
		}
		nanotime(&tn->tn_ctime);
	}
	TMPFS_UNLOCK(tm);
	return error;
}

static int
tmpfs_link(struct vnop_link_args *ap)
{
	vnode_t vp = ap->a_vp;
	vnode_t tdvp = ap->a_tdvp;
	struct componentname *cnp = ap->a_cnp;
	struct tmpfs_mount *tm = VFSTOTMPFS(vnode_mount(tdvp));
	struct tmpfs_node *dnode = VTOTMPFS(tdvp);
	struct tmpfs_node *tn = VTOTMPFS(vp);
	int error;

	if (vp->v_type == VDIR) {
		return EPERM;
	}

	TMPFS_LOCK(tm);
	if (tmpfs_dir_lookup(dnode, cnp->cn_nameptr, cnp->cn_namelen, tm->tm_case_sensitive) != NULL) {
		TMPFS_UNLOCK(tm);
		return EEXIST;
	}

	error = tmpfs_dir_add_entry(dnode, cnp->cn_nameptr, cnp->cn_namelen, tn->tn_ino);
	if (error == 0) {
		tn->tn_nlink++;
		nanotime(&tn->tn_ctime);
	}
	TMPFS_UNLOCK(tm);
	return error;
}

static int
tmpfs_rename(struct vnop_rename_args *ap)
{
	vnode_t fdvp = ap->a_fdvp;
	vnode_t fvp = ap->a_fvp;
	struct componentname *fcnp = ap->a_fcnp;
	vnode_t tdvp = ap->a_tdvp;
	vnode_t tvp = ap->a_tvp;
	struct componentname *tcnp = ap->a_tcnp;
	struct tmpfs_mount *tm = VFSTOTMPFS(vnode_mount(fdvp));
	struct tmpfs_node *fdnode = VTOTMPFS(fdvp);
	struct tmpfs_node *tdnode = VTOTMPFS(tdvp);
	struct tmpfs_node *fnode = VTOTMPFS(fvp);
	int error;

	TMPFS_LOCK(tm);

	if (tvp != NULLVP) {
		struct tmpfs_node *tnode = VTOTMPFS(tvp);
		if (tvp->v_type == VDIR) {
			if (tnode->dir.tn_num_entries != 0) {
				TMPFS_UNLOCK(tm);
				return ENOTEMPTY;
			}
			tdnode->tn_nlink--;
		}
		tmpfs_dir_remove_entry(tdnode, tcnp->cn_nameptr, tcnp->cn_namelen, tm->tm_case_sensitive);
		if (tnode->tn_nlink > 0) {
			tnode->tn_nlink--;
		}
	}

	error = tmpfs_dir_add_entry(tdnode, tcnp->cn_nameptr, tcnp->cn_namelen, fnode->tn_ino);
	if (error != 0) {
		TMPFS_UNLOCK(tm);
		return error;
	}

	tmpfs_dir_remove_entry(fdnode, fcnp->cn_nameptr, fcnp->cn_namelen, tm->tm_case_sensitive);

	if (fvp->v_type == VDIR && fdvp != tdvp) {
		fnode->dir.tn_parent_ino = tdnode->tn_ino;
		fdnode->tn_nlink--;
		tdnode->tn_nlink++;
	}

	nanotime(&fnode->tn_ctime);
	TMPFS_UNLOCK(tm);
	return 0;
}

static int
tmpfs_mkdir(struct vnop_mkdir_args *ap)
{
	vnode_t dvp = ap->a_dvp;
	vnode_t *vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	struct vnode_attr *vap = ap->a_vap;
	struct tmpfs_mount *tm = VFSTOTMPFS(vnode_mount(dvp));
	struct tmpfs_node *dnode = VTOTMPFS(dvp);
	struct tmpfs_node *tn = NULL;
	int error;

	*vpp = NULLVP;

	TMPFS_LOCK(tm);
	if (tmpfs_dir_lookup(dnode, cnp->cn_nameptr, cnp->cn_namelen, tm->tm_case_sensitive) != NULL) {
		TMPFS_UNLOCK(tm);
		return EEXIST;
	}

	mode_t mode = (vap->va_mode & ALLPERMS);
	uid_t uid = VATTR_IS_ACTIVE(vap, va_uid) ? vap->va_uid : kauth_cred_getuid(vfs_context_ucred(ap->a_context));
	gid_t gid = VATTR_IS_ACTIVE(vap, va_gid) ? vap->va_gid : dnode->tn_gid;

	error = tmpfs_alloc_node(tm, VDIR, mode, uid, gid, 0, &tn);
	if (error != 0) {
		TMPFS_UNLOCK(tm);
		return error;
	}
	tn->dir.tn_parent_ino = dnode->tn_ino;

	error = tmpfs_dir_add_entry(dnode, cnp->cn_nameptr, cnp->cn_namelen, tn->tn_ino);
	if (error != 0) {
		tmpfs_free_node(tn);
		TMPFS_UNLOCK(tm);
		return error;
	}
	dnode->tn_nlink++;

	error = tmpfs_vget_node(vnode_mount(dvp), tn, dvp, cnp, vpp);
	TMPFS_UNLOCK(tm);
	return error;
}

static int
tmpfs_rmdir(struct vnop_rmdir_args *ap)
{
	vnode_t dvp = ap->a_dvp;
	vnode_t vp = ap->a_vp;
	struct componentname *cnp = ap->a_cnp;
	struct tmpfs_mount *tm = VFSTOTMPFS(vnode_mount(dvp));
	struct tmpfs_node *dnode = VTOTMPFS(dvp);
	struct tmpfs_node *tn = VTOTMPFS(vp);
	int error;

	if (vp->v_type != VDIR) {
		return ENOTDIR;
	}

	TMPFS_LOCK(tm);
	if (tn->dir.tn_num_entries != 0) {
		TMPFS_UNLOCK(tm);
		return ENOTEMPTY;
	}

	error = tmpfs_dir_remove_entry(dnode, cnp->cn_nameptr, cnp->cn_namelen, tm->tm_case_sensitive);
	if (error == 0) {
		dnode->tn_nlink--;
		tn->tn_nlink = 0;
		nanotime(&tn->tn_ctime);
	}
	TMPFS_UNLOCK(tm);
	return error;
}

static int
tmpfs_symlink(struct vnop_symlink_args *ap)
{
	vnode_t dvp = ap->a_dvp;
	vnode_t *vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	struct vnode_attr *vap = ap->a_vap;
	const char *target = ap->a_target;
	struct tmpfs_mount *tm = VFSTOTMPFS(vnode_mount(dvp));
	struct tmpfs_node *dnode = VTOTMPFS(dvp);
	struct tmpfs_node *tn = NULL;
	int error;

	*vpp = NULLVP;

	TMPFS_LOCK(tm);
	if (tmpfs_dir_lookup(dnode, cnp->cn_nameptr, cnp->cn_namelen, tm->tm_case_sensitive) != NULL) {
		TMPFS_UNLOCK(tm);
		return EEXIST;
	}

	size_t tlen = strlen(target);
	mode_t mode = (vap->va_mode & ALLPERMS);
	uid_t uid = VATTR_IS_ACTIVE(vap, va_uid) ? vap->va_uid : kauth_cred_getuid(vfs_context_ucred(ap->a_context));
	gid_t gid = VATTR_IS_ACTIVE(vap, va_gid) ? vap->va_gid : dnode->tn_gid;

	error = tmpfs_alloc_node(tm, VLNK, mode, uid, gid, 0, &tn);
	if (error != 0) {
		TMPFS_UNLOCK(tm);
		return error;
	}

	tn->link.tn_target = kalloc_data(tlen + 1, Z_WAITOK);
	if (tn->link.tn_target == NULL) {
		tmpfs_free_node(tn);
		TMPFS_UNLOCK(tm);
		return ENOMEM;
	}
	bcopy(target, tn->link.tn_target, tlen);
	tn->link.tn_target[tlen] = '\0';
	tn->link.tn_target_len = tlen;

	error = tmpfs_dir_add_entry(dnode, cnp->cn_nameptr, cnp->cn_namelen, tn->tn_ino);
	if (error != 0) {
		tmpfs_free_node(tn);
		TMPFS_UNLOCK(tm);
		return error;
	}

	error = tmpfs_vget_node(vnode_mount(dvp), tn, dvp, cnp, vpp);
	TMPFS_UNLOCK(tm);
	return error;
}

static int
tmpfs_readlink(struct vnop_readlink_args *ap)
{
	vnode_t vp = ap->a_vp;
	struct tmpfs_mount *tm = VFSTOTMPFS(vnode_mount(vp));
	struct tmpfs_node *tn = VTOTMPFS(vp);
	int error = 0;

	if (vp->v_type != VLNK) {
		return EINVAL;
	}

	TMPFS_LOCK(tm);
	if (tn->link.tn_target != NULL) {
		error = uiomove(tn->link.tn_target, (int)tn->link.tn_target_len, ap->a_uio);
	}
	nanotime(&tn->tn_atime);
	TMPFS_UNLOCK(tm);
	return error;
}

static int
tmpfs_readdir(struct vnop_readdir_args *ap)
{
	vnode_t vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	struct tmpfs_mount *tm = VFSTOTMPFS(vnode_mount(vp));
	struct tmpfs_node *dnode = VTOTMPFS(vp);
	struct dirent dirent;
	int numdirent = 0, eof = 0, error = 0;
	off_t offset = uio_offset(uio);

	if (vp->v_type != VDIR) {
		return ENOTDIR;
	}

	TMPFS_LOCK(tm);

	while (uio_resid(uio) > 0) {
		const char *name;
		size_t namlen;
		uint64_t ino;
		uint8_t dtype;
		uint64_t next_cookie;

		bzero(&dirent, sizeof(dirent));

		if (offset == 0) {
			name = ".";
			namlen = 1;
			ino = dnode->tn_ino;
			dtype = DT_DIR;
			next_cookie = 1;
		} else if (offset == 1) {
			name = "..";
			namlen = 2;
			ino = dnode->dir.tn_parent_ino;
			dtype = DT_DIR;
			next_cookie = 2;
		} else {
			struct tmpfs_dirent *de;
			struct tmpfs_dirent *best = NULL;
			LIST_FOREACH(de, &dnode->dir.tn_dirlist, td_entries) {
				if (de->td_cookie >= (uint64_t)offset) {
					if (best == NULL || de->td_cookie < best->td_cookie) {
						best = de;
					}
				}
			}
			if (best == NULL) {
				eof = 1;
				break;
			}
			name = best->td_name;
			namlen = best->td_namelen;
			ino = best->td_ino;
			dtype = DT_UNKNOWN;
			struct tmpfs_node *tn;
			LIST_FOREACH(tn, &tm->tm_nodes, tn_entries) {
				if (tn->tn_ino == ino) {
					dtype = tmpfs_vtype_to_dtype(tn->tn_type);
					break;
				}
			}
			next_cookie = best->td_cookie + 1;
		}

		dirent.d_ino = ino;
		dirent.d_type = dtype;
		dirent.d_namlen = (uint8_t)namlen;
		dirent.d_reclen = (uint16_t)TMPFS_DIRSIZ(namlen);

		if (uio_resid(uio) < dirent.d_reclen) {
			break;
		}

		bcopy(name, dirent.d_name, namlen);
		dirent.d_name[namlen] = '\0';

		TMPFS_UNLOCK(tm);
		error = uiomove((caddr_t)&dirent, dirent.d_reclen, uio);
		TMPFS_LOCK(tm);

		if (error != 0) {
			break;
		}
		offset = (off_t)next_cookie;
		numdirent++;
	}

	uio_setoffset(uio, offset);
	if (ap->a_eofflag) {
		*ap->a_eofflag = eof;
	}
	if (ap->a_numdirent) {
		*ap->a_numdirent = numdirent;
	}

	nanotime(&dnode->tn_atime);
	TMPFS_UNLOCK(tm);
	return error;
}

static int
tmpfs_inactive(struct vnop_inactive_args *ap)
{
	vnode_t vp = ap->a_vp;
	struct tmpfs_node *tn = VTOTMPFS(vp);

	if (tn->tn_nlink == 0) {
		vnode_recycle(vp);
	}
	return 0;
}

static int
tmpfs_reclaim(struct vnop_reclaim_args *ap)
{
	vnode_t vp = ap->a_vp;
	struct tmpfs_mount *tm = VFSTOTMPFS(vnode_mount(vp));
	struct tmpfs_node *tn = VTOTMPFS(vp);

	TMPFS_LOCK(tm);
	tn->tn_vp = NULLVP;
	tn->tn_vid = 0;
	if (tn->tn_nlink == 0) {
		tmpfs_free_node(tn);
	}
	TMPFS_UNLOCK(tm);
	return 0;
}

static int
tmpfs_pathconf(struct vnop_pathconf_args *ap)
{
	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*ap->a_retval = 32767;
		return 0;
	case _PC_NAME_MAX:
		*ap->a_retval = 255;
		return 0;
	case _PC_PATH_MAX:
		*ap->a_retval = 1024;
		return 0;
	case _PC_CHOWN_RESTRICTED:
		*ap->a_retval = 1;
		return 0;
	case _PC_NO_TRUNC:
		*ap->a_retval = 1;
		return 0;
	default:
		return EINVAL;
	}
}

static int
tmpfs_pagein(struct vnop_pagein_args *ap)
{
	vnode_t vp = ap->a_vp;
	upl_t upl = ap->a_pl;
	struct tmpfs_mount *tm = VFSTOTMPFS(vnode_mount(vp));
	struct tmpfs_node *tn = VTOTMPFS(vp);
	vm_offset_t ioaddr = 0;
	kern_return_t kr;
	int error = 0;

	if (vp->v_type != VREG) {
		return EINVAL;
	}

	kr = ubc_upl_map(upl, &ioaddr);
	if (kr != KERN_SUCCESS) {
		return EIO;
	}

	char *dst = (char *)ioaddr + ap->a_pl_offset;
	off_t f_offset = ap->a_f_offset;
	size_t size = ap->a_size;

	TMPFS_LOCK(tm);
	for (size_t copied = 0; copied < size; ) {
		off_t cur = f_offset + (off_t)copied;
		if (cur >= tn->reg.tn_size) {
			bzero(dst + copied, size - copied);
			break;
		}
		size_t pindex = (size_t)(cur / TMPFS_PAGE_SIZE);
		size_t poff = (size_t)(cur % TMPFS_PAGE_SIZE);
		size_t chunk = TMPFS_PAGE_SIZE - poff;
		if (chunk > (size - copied)) {
			chunk = size - copied;
		}

		void *pg = (pindex < tn->reg.tn_npages) ? tn->reg.tn_pages[pindex] : NULL;
		if (pg != NULL) {
			bcopy((char *)pg + poff, dst + copied, chunk);
		} else {
			bzero(dst + copied, chunk);
		}
		copied += chunk;
	}
	TMPFS_UNLOCK(tm);

	ubc_upl_unmap(upl);

	if ((ap->a_flags & UPL_NOCOMMIT) == 0) {
		ubc_upl_commit_range(upl, ap->a_pl_offset, (upl_size_t)size, UPL_COMMIT_FREE_ON_EMPTY);
	}
	return error;
}

static int
tmpfs_pageout(struct vnop_pageout_args *ap)
{
	vnode_t vp = ap->a_vp;
	upl_t upl = ap->a_pl;
	struct tmpfs_mount *tm = VFSTOTMPFS(vnode_mount(vp));
	struct tmpfs_node *tn = VTOTMPFS(vp);
	vm_offset_t ioaddr = 0;
	kern_return_t kr;
	int error = 0;

	if (vp->v_type != VREG) {
		return EINVAL;
	}

	kr = ubc_upl_map(upl, &ioaddr);
	if (kr != KERN_SUCCESS) {
		return EIO;
	}

	char *src = (char *)ioaddr + ap->a_pl_offset;
	off_t f_offset = ap->a_f_offset;
	size_t size = ap->a_size;

	TMPFS_LOCK(tm);
	if (f_offset + (off_t)size > tn->reg.tn_size) {
		tmpfs_grow_file(tn, f_offset + (off_t)size);
	}

	for (size_t copied = 0; copied < size; ) {
		off_t cur = f_offset + (off_t)copied;
		size_t pindex = (size_t)(cur / TMPFS_PAGE_SIZE);
		size_t poff = (size_t)(cur % TMPFS_PAGE_SIZE);
		size_t chunk = TMPFS_PAGE_SIZE - poff;
		if (chunk > (size - copied)) {
			chunk = size - copied;
		}

		if (pindex >= tn->reg.tn_npages || tn->reg.tn_pages[pindex] == NULL) {
			if (tm->tm_pages_used >= tm->tm_max_pages) {
				error = ENOSPC;
				break;
			}
			void *pg = kalloc_data(TMPFS_PAGE_SIZE, Z_WAITOK | Z_ZERO);
			if (pg == NULL) {
				error = ENOSPC;
				break;
			}
			tn->reg.tn_pages[pindex] = pg;
			tm->tm_pages_used++;
		}
		bcopy(src + copied, (char *)tn->reg.tn_pages[pindex] + poff, chunk);
		copied += chunk;
	}
	nanotime(&tn->tn_mtime);
	tn->tn_ctime = tn->tn_mtime;
	TMPFS_UNLOCK(tm);

	ubc_upl_unmap(upl);

	if ((ap->a_flags & UPL_NOCOMMIT) == 0) {
		ubc_upl_commit_range(upl, ap->a_pl_offset, (upl_size_t)size,
		    UPL_COMMIT_FREE_ON_EMPTY | UPL_COMMIT_CLEAR_DIRTY);
	}
	return error;
}

const struct vnodeopv_entry_desc tmpfs_vnodeop_entries[] = {
	{ .opve_op = &vnop_default_desc, .opve_impl = (VOPFUNC) vn_default_error },
	{ .opve_op = &vnop_lookup_desc, .opve_impl = (VOPFUNC) tmpfs_lookup },
	{ .opve_op = &vnop_create_desc, .opve_impl = (VOPFUNC) tmpfs_create },
	{ .opve_op = &vnop_open_desc, .opve_impl = (VOPFUNC) tmpfs_open },
	{ .opve_op = &vnop_close_desc, .opve_impl = (VOPFUNC) nop_close },
	{ .opve_op = &vnop_getattr_desc, .opve_impl = (VOPFUNC) tmpfs_getattr },
	{ .opve_op = &vnop_setattr_desc, .opve_impl = (VOPFUNC) tmpfs_setattr },
	{ .opve_op = &vnop_read_desc, .opve_impl = (VOPFUNC) tmpfs_read },
	{ .opve_op = &vnop_write_desc, .opve_impl = (VOPFUNC) tmpfs_write },
	{ .opve_op = &vnop_mmap_desc, .opve_impl = (VOPFUNC) nop_mmap },
	{ .opve_op = &vnop_fsync_desc, .opve_impl = (VOPFUNC) nop_fsync },
	{ .opve_op = &vnop_remove_desc, .opve_impl = (VOPFUNC) tmpfs_remove },
	{ .opve_op = &vnop_link_desc, .opve_impl = (VOPFUNC) tmpfs_link },
	{ .opve_op = &vnop_rename_desc, .opve_impl = (VOPFUNC) tmpfs_rename },
	{ .opve_op = &vnop_mkdir_desc, .opve_impl = (VOPFUNC) tmpfs_mkdir },
	{ .opve_op = &vnop_rmdir_desc, .opve_impl = (VOPFUNC) tmpfs_rmdir },
	{ .opve_op = &vnop_symlink_desc, .opve_impl = (VOPFUNC) tmpfs_symlink },
	{ .opve_op = &vnop_readdir_desc, .opve_impl = (VOPFUNC) tmpfs_readdir },
	{ .opve_op = &vnop_readlink_desc, .opve_impl = (VOPFUNC) tmpfs_readlink },
	{ .opve_op = &vnop_inactive_desc, .opve_impl = (VOPFUNC) tmpfs_inactive },
	{ .opve_op = &vnop_reclaim_desc, .opve_impl = (VOPFUNC) tmpfs_reclaim },
	{ .opve_op = &vnop_pathconf_desc, .opve_impl = (VOPFUNC) tmpfs_pathconf },
	{ .opve_op = &vnop_pagein_desc, .opve_impl = (VOPFUNC) tmpfs_pagein },
	{ .opve_op = &vnop_pageout_desc, .opve_impl = (VOPFUNC) tmpfs_pageout },
	{ .opve_op = (struct vnodeop_desc *) NULL, .opve_impl = (VOPFUNC) NULL }
};

const struct vnodeopv_desc tmpfs_vnodeop_opv_desc = {
	.opv_desc_vector_p = &tmpfs_vnodeop_p,
	.opv_desc_ops = tmpfs_vnodeop_entries
};
