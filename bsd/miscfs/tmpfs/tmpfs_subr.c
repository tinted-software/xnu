// SPDX-License-Identifier: GPL-2.0
#include <miscfs/tmpfs/tmpfs.h>
#include <sys/vnode_internal.h>
#include <sys/mount_internal.h>
#include <sys/errno.h>

int
tmpfs_alloc_node(struct tmpfs_mount *tm, enum vtype type, mode_t mode,
    uid_t uid, gid_t gid, uint64_t ino, struct tmpfs_node **out_node)
{
	struct tmpfs_node *tn;

	if (tm->tm_nodes_used >= tm->tm_max_nodes) {
		return ENOSPC;
	}

	tn = kalloc_type(struct tmpfs_node, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	tn->tn_mount = tm;
	tn->tn_ino = ino ? ino : tm->tm_next_ino++;
	tn->tn_type = type;
	tn->tn_mode = mode;
	tn->tn_uid = uid;
	tn->tn_gid = gid;
	tn->tn_nlink = (type == VDIR) ? 2 : 1;

	nanotime(&tn->tn_atime);
	tn->tn_mtime = tn->tn_atime;
	tn->tn_ctime = tn->tn_atime;
	tn->tn_btime = tn->tn_atime;

	if (type == VDIR) {
		LIST_INIT(&tn->dir.tn_dirlist);
		tn->dir.tn_next_cookie = 2;
	}

	LIST_INSERT_HEAD(&tm->tm_nodes, tn, tn_entries);
	tm->tm_nodes_used++;
	*out_node = tn;
	return 0;
}

void
tmpfs_free_node(struct tmpfs_node *tn)
{
	struct tmpfs_mount *tm = tn->tn_mount;

	LIST_REMOVE(tn, tn_entries);
	tm->tm_nodes_used--;

	if (tn->tn_type == VREG) {
		tmpfs_truncate_file(tn, 0);
		if (tn->reg.tn_pages != NULL) {
			kfree_data(tn->reg.tn_pages, tn->reg.tn_npages * sizeof(void *));
			tn->reg.tn_pages = NULL;
		}
	} else if (tn->tn_type == VDIR) {
		struct tmpfs_dirent *de, *tde;
		LIST_FOREACH_SAFE(de, &tn->dir.tn_dirlist, td_entries, tde) {
			LIST_REMOVE(de, td_entries);
			kfree_data(de, sizeof(struct tmpfs_dirent) + de->td_namelen + 1);
		}
	} else if (tn->tn_type == VLNK) {
		if (tn->link.tn_target != NULL) {
			kfree_data(tn->link.tn_target, tn->link.tn_target_len + 1);
		}
	}
	kfree_type(struct tmpfs_node, tn);
}

int
tmpfs_vget_node(mount_t mp, struct tmpfs_node *tn, vnode_t dvp,
    struct componentname *cnp, vnode_t *vpp)
{
	struct tmpfs_mount *tm = tn->tn_mount;
	struct vnode_fsparam param;
	vnode_t vp;
	uint32_t vid;
	int error;

retry:
	if (tn->tn_vp != NULL) {
		vp = tn->tn_vp;
		vid = tn->tn_vid;
		TMPFS_UNLOCK(tm);
		error = vnode_getwithvid(vp, vid);
		TMPFS_LOCK(tm);
		if (error == 0) {
			*vpp = vp;
			return 0;
		}
		/* Raced with recycle/reclaim, retry */
		goto retry;
	}

	if (tn->tn_creating) {
		msleep(tn, &tm->tm_lock, PINOD, "tmpfs_vget", NULL);
		goto retry;
	}

	tn->tn_creating = true;
	TMPFS_UNLOCK(tm);

	bzero(&param, sizeof(param));
	param.vnfs_mp = mp;
	param.vnfs_vtype = tn->tn_type;
	param.vnfs_str = "tmpfs";
	param.vnfs_dvp = dvp;
	param.vnfs_fsnode = tn;
	param.vnfs_vops = tmpfs_vnodeop_p;
	param.vnfs_markroot = (tn->tn_ino == TMPFS_ROOT_INO);
	param.vnfs_marksystem = 0;
	param.vnfs_rdev = tn->tn_rdev;
	param.vnfs_filesize = (tn->tn_type == VREG) ? tn->reg.tn_size : 0;
	param.vnfs_cnp = cnp;
	param.vnfs_flags = (cnp != NULL && dvp != NULLVP && (cnp->cn_flags & MAKEENTRY)) ? 0 : VNFS_NOCACHE;

	error = vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &param, &vp);

	TMPFS_LOCK(tm);
	tn->tn_creating = false;
	wakeup(tn);

	if (error == 0) {
		vnode_settag(vp, VT_OTHER);
		tn->tn_vp = vp;
		tn->tn_vid = vnode_vid(vp);
		*vpp = vp;
	}
	return error;
}

int
tmpfs_dir_add_entry(struct tmpfs_node *dnode, const char *name,
    size_t namelen, uint64_t ino)
{
	struct tmpfs_dirent *de;

	de = kalloc_data(sizeof(struct tmpfs_dirent) + namelen + 1, Z_WAITOK);
	if (de == NULL) {
		return ENOSPC;
	}
	de->td_ino = ino;
	de->td_cookie = dnode->dir.tn_next_cookie++;
	de->td_namelen = (uint32_t)namelen;
	bcopy(name, de->td_name, namelen);
	de->td_name[namelen] = '\0';

	LIST_INSERT_HEAD(&dnode->dir.tn_dirlist, de, td_entries);
	dnode->dir.tn_num_entries++;
	nanotime(&dnode->tn_mtime);
	dnode->tn_ctime = dnode->tn_mtime;
	return 0;
}

struct tmpfs_dirent *
tmpfs_dir_lookup(struct tmpfs_node *dnode, const char *name,
    size_t namelen, bool case_sensitive)
{
	struct tmpfs_dirent *de;

	LIST_FOREACH(de, &dnode->dir.tn_dirlist, td_entries) {
		if (de->td_namelen != namelen) {
			continue;
		}
		if (case_sensitive) {
			if (bcmp(de->td_name, name, namelen) == 0) {
				return de;
			}
		} else {
			if (strncasecmp(de->td_name, name, namelen) == 0) {
				return de;
			}
		}
	}
	return NULL;
}

int
tmpfs_dir_remove_entry(struct tmpfs_node *dnode, const char *name,
    size_t namelen, bool case_sensitive)
{
	struct tmpfs_dirent *de;

	de = tmpfs_dir_lookup(dnode, name, namelen, case_sensitive);
	if (de == NULL) {
		return ENOENT;
	}
	LIST_REMOVE(de, td_entries);
	dnode->dir.tn_num_entries--;
	nanotime(&dnode->tn_mtime);
	dnode->tn_ctime = dnode->tn_mtime;
	kfree_data(de, sizeof(struct tmpfs_dirent) + de->td_namelen + 1);
	return 0;
}

int
tmpfs_truncate_file(struct tmpfs_node *tn, off_t new_size)
{
	if (new_size < tn->reg.tn_size) {
		size_t new_pages = (size_t)((new_size + TMPFS_PAGE_SIZE - 1) / TMPFS_PAGE_SIZE);
		for (size_t i = new_pages; i < tn->reg.tn_npages; i++) {
			if (tn->reg.tn_pages[i] != NULL) {
				kfree_data(tn->reg.tn_pages[i], TMPFS_PAGE_SIZE);
				tn->reg.tn_pages[i] = NULL;
				if (tn->tn_mount->tm_pages_used > 0) {
					tn->tn_mount->tm_pages_used--;
				}
			}
		}
		size_t poff = (size_t)(new_size % TMPFS_PAGE_SIZE);
		if (poff != 0 && new_pages > 0 && tn->reg.tn_pages[new_pages - 1] != NULL) {
			bzero((char *)tn->reg.tn_pages[new_pages - 1] + poff, TMPFS_PAGE_SIZE - poff);
		}
	}
	tn->reg.tn_size = new_size;
	nanotime(&tn->tn_mtime);
	tn->tn_ctime = tn->tn_mtime;
	return 0;
}

int
tmpfs_grow_file(struct tmpfs_node *tn, off_t new_size)
{
	size_t needed_pages = (size_t)((new_size + TMPFS_PAGE_SIZE - 1) / TMPFS_PAGE_SIZE);

	if (needed_pages > tn->reg.tn_npages) {
		size_t new_cap = needed_pages < 8 ? 8 : (needed_pages * 2);
		void **new_pages = kalloc_data(new_cap * sizeof(void *), Z_WAITOK | Z_ZERO);
		if (new_pages == NULL) {
			return ENOSPC;
		}
		if (tn->reg.tn_pages != NULL) {
			bcopy(tn->reg.tn_pages, new_pages, tn->reg.tn_npages * sizeof(void *));
			kfree_data(tn->reg.tn_pages, tn->reg.tn_npages * sizeof(void *));
		}
		tn->reg.tn_pages = new_pages;
		tn->reg.tn_npages = new_cap;
	}
	tn->reg.tn_size = new_size;
	nanotime(&tn->tn_mtime);
	tn->tn_ctime = tn->tn_mtime;
	return 0;
}
