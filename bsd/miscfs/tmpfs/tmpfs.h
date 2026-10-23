// SPDX-License-Identifier: GPL-2.0
#ifndef _MISCFS_TMPFS_TMPFS_H_
#define _MISCFS_TMPFS_TMPFS_H_

#include <sys/param.h>
#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/kauth.h>
#include <kern/locks.h>
#include <kern/kalloc.h>
#include <libkern/libkern.h>

#define TMPFS_PAGE_SIZE     16384
#define TMPFS_ROOT_INO      2
#define TMPFS_DEFAULT_MAX_NODES 100000
#define TMPFS_DEFAULT_MAX_PAGES 65536

struct tmpfs_args {
	uint64_t ta_max_pages;
	uint64_t ta_max_nodes;
	uint64_t ta_case_sensitive;
};

struct tmpfs_dirent {
	LIST_ENTRY(tmpfs_dirent) td_entries;
	uint64_t                td_ino;
	uint64_t                td_cookie;
	uint32_t                td_namelen;
	char                    td_name[0];
};

struct tmpfs_node {
	LIST_ENTRY(tmpfs_node)  tn_entries;
	struct tmpfs_mount     *tn_mount;
	uint64_t                tn_ino;
	enum vtype              tn_type;
	mode_t                  tn_mode;
	uid_t                   tn_uid;
	gid_t                   tn_gid;
	uint32_t                tn_nlink;
	uint32_t                tn_flags;
	struct timespec         tn_atime;
	struct timespec         tn_mtime;
	struct timespec         tn_ctime;
	struct timespec         tn_btime;
	dev_t                   tn_rdev;

	vnode_t                 tn_vp;
	uint32_t                tn_vid;
	bool                    tn_creating;

	union {
		struct {
			off_t   tn_size;
			void  **tn_pages;
			size_t  tn_npages;
		} reg;
		struct {
			LIST_HEAD(, tmpfs_dirent) tn_dirlist;
			uint64_t tn_parent_ino;
			uint64_t tn_next_cookie;
			uint32_t tn_num_entries;
		} dir;
		struct {
			char   *tn_target;
			size_t  tn_target_len;
		} link;
	};
};

struct tmpfs_mount {
	mount_t                 tm_mp;
	lck_mtx_t               tm_lock;
	uint64_t                tm_next_ino;
	uint64_t                tm_max_pages;
	uint64_t                tm_pages_used;
	uint64_t                tm_max_nodes;
	uint64_t                tm_nodes_used;
	bool                    tm_case_sensitive;
	struct tmpfs_node      *tm_root;
	LIST_HEAD(, tmpfs_node) tm_nodes;
};

#define VFSTOTMPFS(mp)  ((struct tmpfs_mount *)vfs_fsprivate(mp))
#define VTOTMPFS(vp)    ((struct tmpfs_node *)vnode_fsnode(vp))

#define TMPFS_LOCK(tm)   lck_mtx_lock(&(tm)->tm_lock)
#define TMPFS_UNLOCK(tm) lck_mtx_unlock(&(tm)->tm_lock)

extern lck_grp_t tmpfs_lck_grp;
extern int (**tmpfs_vnodeop_p)(void *);
extern const struct vfsops tmpfs_vfsops;
extern const struct vnodeopv_desc tmpfs_vnodeop_opv_desc;

/* Subroutines */
int  tmpfs_alloc_node(struct tmpfs_mount *tm, enum vtype type, mode_t mode,
    uid_t uid, gid_t gid, uint64_t ino, struct tmpfs_node **out_node);
void tmpfs_free_node(struct tmpfs_node *tn);
int  tmpfs_vget_node(mount_t mp, struct tmpfs_node *tn, vnode_t dvp,
    struct componentname *cnp, vnode_t *vpp);
int  tmpfs_dir_add_entry(struct tmpfs_node *dnode, const char *name,
    size_t namelen, uint64_t ino);
struct tmpfs_dirent *tmpfs_dir_lookup(struct tmpfs_node *dnode,
    const char *name, size_t namelen, bool case_sensitive);
int  tmpfs_dir_remove_entry(struct tmpfs_node *dnode, const char *name,
    size_t namelen, bool case_sensitive);
int  tmpfs_truncate_file(struct tmpfs_node *tn, off_t new_size);
int  tmpfs_grow_file(struct tmpfs_node *tn, off_t new_size);

#endif /* _MISCFS_TMPFS_TMPFS_H_ */
