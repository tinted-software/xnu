// SPDX-License-Identifier: MIT OR Apache-2.0

#ifndef APFSRO_H
#define APFSRO_H

#include <kern/locks.h>
#include <stdint.h>
#include <sys/kernel_types.h>
#include <sys/mount.h>
#include <sys/queue.h>
#include <sys/vnode.h>

/*
 * apfsro is a read-only APFS root filesystem for a boot device.
 *
 * The root device (the boot ramdisk md0, or a disk such as virtio-blk) holds a
 * raw APFS container. All on-disk parsing is done by the Rust reader in
 * rust/xnurc/src/apfs.rs (hadris-apfs), which reads the container through a
 * callback backed by the root device vnode. It builds an in-memory index of
 * the volume once, and answers lookup, readdir, readlink and extent queries
 * from that index. This filesystem is the VFS glue: one vnode per inode
 * (hashed by inode number), UBC-backed file data paged in through the generic
 * cluster layer, with VNOP_BLOCKMAP translating file offsets to device
 * offsets using the file's APFS extents.
 *
 * Because paging goes through blockmap/strategy against the device, files
 * may have any number of extents (and holes); nothing requires the image
 * writer to lay files out contiguously.
 */

/*
 * C view of the Rust ABI. Every function returns 0 or an errno. These
 * structures mirror the #[repr(C)] types in rust/xnurc/src/apfs.rs.
 */
struct apfsro_time {
	int64_t sec;
	int64_t nsec;
};

struct apfsro_attr {
	uint64_t ino;
	uint64_t size;
	uint64_t alloc;
	uint32_t mode;          /* st_mode: S_IFMT bits | permission bits */
	uint32_t nlink;
	uint32_t uid;
	uint32_t gid;
	uint32_t flags;         /* st_flags (APFS bsd_flags) */
	uint32_t reserved;
	struct apfsro_time atime;
	struct apfsro_time mtime;
	struct apfsro_time ctime;
	struct apfsro_time btime;
};

#define APFSRO_NAME_MAX 255

struct apfsro_dirent {
	uint64_t ino;
	uint64_t next_cookie;
	uint32_t mode;          /* S_IFMT bits only */
	uint32_t name_len;
	uint32_t valid;         /* 0: no entry at this cookie (end of directory) */
	uint32_t reserved;
	char     name[APFSRO_NAME_MAX + 1];
};

#define APFSRO_STATFS_CASE_INSENSITIVE  0x1

struct apfsro_statfs {
	uint32_t block_size;
	uint32_t flags;         /* APFSRO_STATFS_* */
	uint64_t blocks;
	uint64_t bfree;
	uint64_t files;
};

#define APFSRO_MAP_HOLE UINT64_MAX

struct apfsro_map {
	uint64_t phys;          /* byte offset in the container, or APFSRO_MAP_HOLE */
	uint64_t run;           /* contiguous bytes from the queried offset */
};

/* Reads len bytes at byte offset of the root device; returns 0 or an errno. */
typedef int (*apfsro_read_fn_t)(void *ctx, uint64_t offset, void *buf, size_t len);

int      xnu_rc_apfs_mount(apfsro_read_fn_t read, void *ctx, uint64_t len, void **handle);
void     xnu_rc_apfs_unmount(void *handle);
uint64_t xnu_rc_apfs_root_ino(void);
int      xnu_rc_apfs_statfs(void *handle, struct apfsro_statfs *out);
int      xnu_rc_apfs_getattr(void *handle, uint64_t ino, struct apfsro_attr *out);
int      xnu_rc_apfs_lookup(void *handle, uint64_t dir, const char *name, size_t name_len,
    struct apfsro_attr *out);
int      xnu_rc_apfs_parent(void *handle, uint64_t dir, uint64_t *out);
int      xnu_rc_apfs_readdir(void *handle, uint64_t dir, uint64_t cookie,
    struct apfsro_dirent *out);
int      xnu_rc_apfs_readlink(void *handle, uint64_t ino, char *buf, size_t buf_len,
    size_t *out_len);
int      xnu_rc_apfs_read(void *handle, uint64_t ino, uint64_t offset, void *buf, size_t len,
    size_t *out_read);
int      xnu_rc_apfs_map(void *handle, uint64_t ino, uint64_t offset, struct apfsro_map *out);

/*
 * Vnodes are hashed by inode number per mount.
 */
#define APFSRO_HASH_SIZE 64
#define APFSRO_HASH(ino) ((unsigned int)((ino) % APFSRO_HASH_SIZE))

/*
 * Per-inode state, hung off v_data. The attributes are cached at vnode
 * creation; the volume is immutable, so they never change.
 */
struct apfsro_node {
	LIST_ENTRY(apfsro_node) an_hash;        /* mount hash chain, under am_hash_mtx */
	mount_t                 an_mp;
	vnode_t                 an_vp;
	uint32_t                an_vid;
	boolean_t               an_hashed;      /* on the hash chain */
	struct apfsro_attr      an_attr;
};

LIST_HEAD(apfsro_hashhead, apfsro_node);

/* apfsro_mount::am_io_state */
enum {
	APFSRO_IO_IDLE,         /* no request */
	APFSRO_IO_PENDING,      /* request posted, thread not done */
	APFSRO_IO_DONE,         /* result in am_io_error */
	APFSRO_IO_STOP,         /* thread asked to exit */
	APFSRO_IO_STOPPED,      /* thread exited */
};

struct apfsro_mount {
	void                   *am_handle;      /* Rust mount; calls serialized by am_rust_mtx */
	vnode_t                 am_devvp;       /* root device the container is read from */

	/*
	 * Device reads run on their own thread: the Rust reader nests ~8 KiB of
	 * frames and the buffer-cache/zalloc path below a read needs several more,
	 * which together overflow one 16 KiB kernel stack. The reader hands each
	 * read to am_io_thread and sleeps; one request is in flight at a time.
	 */
	lck_mtx_t               am_io_mtx;      /* protects the am_io_* fields */
	int                     am_io_state;    /* APFSRO_IO_* */
	uint64_t                am_io_offset;
	void                   *am_io_buf;
	size_t                  am_io_len;
	int                     am_io_error;
	lck_mtx_t               am_rust_mtx;
	lck_mtx_t               am_hash_mtx;    /* protects the hash and node an_hash/an_hashed */
	struct apfsro_hashhead  am_hash[APFSRO_HASH_SIZE];
	uint64_t                am_root_ino;
	int                     am_case_insensitive;
};

#define VFSTOAPFSRO(mp)  ((struct apfsro_mount *)vfs_fsprivate(mp))
#define VTOAPFSRO(vp)    ((struct apfsro_node *)vnode_fsnode(vp))

extern lck_grp_t apfsro_lck_grp;

extern int (**apfsro_vnodeop_p)(void *);
extern const struct vfsops apfsro_vfsops;

int apfsro_mountroot(mount_t mp, vnode_t rvp, vfs_context_t ctx);

/* apfsro_node.c */
int  apfsro_vget_ino(mount_t mp, uint64_t ino, const struct apfsro_attr *attr,
    vnode_t dvp, struct componentname *cnp, vnode_t *vpp);
void apfsro_node_free(vnode_t vp);

/* Serializes calls into the Rust reader. */
#define APFSRO_RUST_LOCK(am)    lck_mtx_lock(&(am)->am_rust_mtx)
#define APFSRO_RUST_UNLOCK(am)  lck_mtx_unlock(&(am)->am_rust_mtx)

#endif /* APFSRO_H */
