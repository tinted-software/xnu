// SPDX-License-Identifier: MIT OR Apache-2.0

/*
 * apfsro vnode management: one vnode per inode, found through a per-mount
 * hash keyed by inode number.
 *
 * Locking: am_hash_mtx protects the hash chains and the an_hashed flag. It is
 * never held across vnode_create() or vnode_getwithvid(): new_vnode() may
 * reclaim another apfsro vnode, and apfsro_reclaim() takes am_hash_mtx.
 */

#include <miscfs/apfsro/apfsro.h>
#include <kern/assert.h>
#include <libkern/libkern.h>
#include <sys/errno.h>
#include <sys/mount_internal.h>
#include <sys/stat.h>
#include <sys/vnode_internal.h>

extern int (**apfsro_vnodeop_p)(void *);

static struct apfsro_node *
apfsro_hash_find(struct apfsro_mount *am, uint64_t ino)
{
	struct apfsro_node *an;

	LIST_FOREACH(an, &am->am_hash[APFSRO_HASH(ino)], an_hash) {
		if (an->an_attr.ino == ino) {
			return an;
		}
	}
	return NULL;
}

/*
 * Take an iocount on the vnode already published for `ino`.
 *
 * Returns 0 with *vpp set, ENOENT if there is no such vnode, or EAGAIN if the
 * vnode exists but is being reclaimed (in which case this has slept until the
 * reclaim unhashed it, so the caller can simply retry).
 */
static int
apfsro_hash_get(struct apfsro_mount *am, uint64_t ino, vnode_t *vpp)
{
	struct apfsro_node *an;
	vnode_t vp;
	uint32_t vid;
	int error;

	lck_mtx_lock(&am->am_hash_mtx);
	an = apfsro_hash_find(am, ino);
	if (an == NULL) {
		lck_mtx_unlock(&am->am_hash_mtx);
		return ENOENT;
	}
	vp = an->an_vp;
	vid = an->an_vid;
	vnode_hold(vp);
	lck_mtx_unlock(&am->am_hash_mtx);

	error = vnode_getwithvid(vp, vid);
	vnode_drop(vp);
	if (error == 0) {
		*vpp = vp;
		return 0;
	}

	/*
	 * The vnode is dead or on its way out; apfsro_reclaim() removes the node
	 * from the hash (under am_hash_mtx) and wakes us. Re-check under the lock
	 * so a reclaim that already finished is not waited for. The sleep is
	 * bounded because `an` may have been freed and its address reused by the
	 * time the lock is retaken, in which case no wakeup is owed to us.
	 */
	lck_mtx_lock(&am->am_hash_mtx);
	if (apfsro_hash_find(am, ino) == an) {
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 10 * 1000 * 1000 };
		(void)msleep(&am->am_hash, &am->am_hash_mtx, PVFS, "apfsro_reclaim", &ts);
	}
	lck_mtx_unlock(&am->am_hash_mtx);
	return EAGAIN;
}

static enum vtype
apfsro_vtype(uint32_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFREG:
		return VREG;
	case S_IFDIR:
		return VDIR;
	case S_IFLNK:
		return VLNK;
	default:
		return VBAD;
	}
}

/*
 * apfsro_vget_ino:
 *   Returns the vnode (with an iocount) for inode `ino`, creating it if needed.
 *   `attr`, when given, must be the inode's current attributes and saves a
 *   trip into the Rust reader if the vnode has to be created. `dvp`/`cnp`
 *   (both optional) describe the lookup that found the inode, so the new vnode
 *   gets a parent and a name.
 */
int
apfsro_vget_ino(mount_t mp, uint64_t ino, const struct apfsro_attr *attr,
    vnode_t dvp, struct componentname *cnp, vnode_t *vpp)
{
	struct apfsro_mount *am = VFSTOAPFSRO(mp);
	struct apfsro_node *an, *existing;
	struct apfsro_attr fetched;
	struct vnode_fsparam param;
	vnode_t vp, evp;
	int error;

	for (;;) {
		error = apfsro_hash_get(am, ino, vpp);
		if (error == 0) {
			return 0;
		}
		if (error == ENOENT) {
			break;
		}
		/* EAGAIN: a dying vnode just went away; look again. */
	}

	if (attr == NULL) {
		APFSRO_RUST_LOCK(am);
		error = xnu_rc_apfs_getattr(am->am_handle, ino, &fetched);
		APFSRO_RUST_UNLOCK(am);
		if (error) {
			return error;
		}
		attr = &fetched;
	}

	if (apfsro_vtype(attr->mode) == VBAD) {
		return ENOTSUP;
	}

	an = kalloc_type(struct apfsro_node, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	an->an_mp = mp;
	an->an_attr = *attr;

	bzero(&param, sizeof(param));
	param.vnfs_mp = mp;
	param.vnfs_vtype = apfsro_vtype(attr->mode);
	param.vnfs_str = "apfs";
	param.vnfs_dvp = dvp;
	param.vnfs_fsnode = an;
	param.vnfs_vops = apfsro_vnodeop_p;
	param.vnfs_markroot = (ino == am->am_root_ino);
	param.vnfs_marksystem = 0;
	param.vnfs_rdev = 0;
	param.vnfs_filesize = (off_t)attr->size;
	param.vnfs_cnp = cnp;
	param.vnfs_flags = (cnp != NULL && dvp != NULLVP && (cnp->cn_flags & MAKEENTRY)) ? 0 : VNFS_NOCACHE;

	error = vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &param, &vp);
	if (error) {
		kfree_type(struct apfsro_node, an);
		return error;
	}
	vnode_settag(vp, VT_APFSRO);
	an->an_vp = vp;
	an->an_vid = vnode_vid(vp);

	/*
	 * Publish the node unless another thread beat us to it, in which case
	 * ours is thrown away: vnode_recycle() makes the final vnode_put()
	 * reclaim it, and an_hashed == FALSE tells apfsro_reclaim() there is
	 * nothing to unhash.
	 */
	lck_mtx_lock(&am->am_hash_mtx);
	existing = apfsro_hash_find(am, ino);
	if (existing == NULL) {
		LIST_INSERT_HEAD(&am->am_hash[APFSRO_HASH(ino)], an, an_hash);
		an->an_hashed = TRUE;
		lck_mtx_unlock(&am->am_hash_mtx);
		*vpp = vp;
		return 0;
	}
	lck_mtx_unlock(&am->am_hash_mtx);

	vnode_recycle(vp);
	vnode_put(vp);

	for (;;) {
		error = apfsro_hash_get(am, ino, &evp);
		if (error == 0) {
			*vpp = evp;
			return 0;
		}
		if (error == ENOENT) {
			/* The winner has already gone away; start over. */
			return apfsro_vget_ino(mp, ino, attr, dvp, cnp, vpp);
		}
	}
}

/*
 * apfsro_node_free:
 *   Called from VNOP_RECLAIM: unhash and free the node, and detach it from
 *   the vnode.
 */
void
apfsro_node_free(vnode_t vp)
{
	struct apfsro_node *an = VTOAPFSRO(vp);
	struct apfsro_mount *am = VFSTOAPFSRO(an->an_mp);

	lck_mtx_lock(&am->am_hash_mtx);
	if (an->an_hashed) {
		LIST_REMOVE(an, an_hash);
		an->an_hashed = FALSE;
	}
	vnode_clearfsnode(vp);
	wakeup(&am->am_hash);
	lck_mtx_unlock(&am->am_hash_mtx);

	kfree_type(struct apfsro_node, an);
}
