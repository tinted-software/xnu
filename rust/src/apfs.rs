// SPDX-License-Identifier: MIT OR Apache-2.0
//! Read-only APFS volume access for the kernel root filesystem.
//!
//! The container is read through a C callback (`ReadFn`) that the filesystem
//! backs with the root device vnode, so the same code serves the boot ramdisk
//! and a real disk (virtio-blk). Mounting validates the checkpoint and resolves
//! the container's sole volume. Queries then descend the volume's filesystem
//! tree by key, as Apple's APFS does: a lookup reads the B-tree path to the
//! records of one object (an inode, a directory's entries, a data stream's
//! extents) instead of loading the volume. File data is read through the same
//! callback.
//!
//! This drives `hadris_apfs::sync::Container` directly instead of `ApfsFs`:
//! `ApfsFs::mount` nests roughly 15 KiB of stack frames, which does not fit on
//! the 16 KiB kernel stack, while the container calls used here peak around
//! 8 KiB. The container also exposes each file's extents, which the kernel
//! needs to map file offsets to device offsets for paging.
//!
//! The C filesystem (bsd/miscfs/apfsro) owns all locking: a mount handle may
//! be used by one caller at a time. Functions return 0 or a Darwin `errno`.
//! Node identifiers are APFS inode numbers (the root directory is 2).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::{ptr, slice};

use hadris_apfs::sync::Container;
use hadris_apfs::types::filesystem::{
    self, stream_size, FileExtentRecord, InodeRecord, OwnedDirectoryEntryRecord,
};
use hadris_apfs::types::volume::APFS_FS_UNENCRYPTED;
use hadris_apfs::types::{ContainerSuperblock, VolumeSuperblock};
use hadris_io::{ErrorKind, ErrorType};
use hadris_storage::sync::BlockDevice;
use hadris_storage::{BlockIndex, BlockSize};

// Darwin errno values (bsd/sys/errno.h).
const ENOENT: i32 = 2;
const EIO: i32 = 5;
const EBUSY: i32 = 16;
const ENOTDIR: i32 = 20;
const EISDIR: i32 = 21;
const EINVAL: i32 = 22;
const EFBIG: i32 = 27;
const EROFS: i32 = 30;
const ENOTSUP: i32 = 45;
const ELOOP: i32 = 62;
const ENAMETOOLONG: i32 = 63;
const ESTALE: i32 = 70;
/// Inappropriate file type or format; reported for a corrupt volume.
const EFTYPE: i32 = 79;
const EOVERFLOW: i32 = 84;

// Darwin st_mode file-type bits (bsd/sys/stat.h).
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;

/// APFS inode number of the volume root directory.
const ROOT_INO: u64 = filesystem::INODE_ROOT_DIRECTORY;
/// Container block size accepted by this reader (and the ramdisk sector size).
const BLOCK_SIZE: u32 = 4096;
/// Container superblock flag: the container is encrypted.
const SB_FLAG_ENCRYPTED: u64 = 4;
/// Longest directory entry name APFS allows.
const NAME_MAX: usize = 255;
/// `ApfsStatfs::flags`: the volume matches names case-insensitively.
const STATFS_CASE_INSENSITIVE: u32 = 0x1;
/// `ApfsMap::phys` value for a hole (reads as zeroes).
const HOLE: u64 = u64::MAX;

/// Reads `len` bytes at byte `offset` of the root device into `buf`; returns 0
/// or a Darwin `errno`. Mirrors `apfsro_read_fn_t` in apfsro.h.
pub type ReadFn =
    unsafe extern "C" fn(ctx: *mut c_void, offset: u64, buf: *mut u8, len: usize) -> i32;

#[derive(Debug)]
pub struct DiskError;

impl core::fmt::Display for DiskError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("root device read failed")
    }
}

impl core::error::Error for DiskError {}

/// The root device, as a `BlockDevice` of `BLOCK_SIZE` blocks.
pub struct Device {
    read: ReadFn,
    ctx: *mut c_void,
    blocks: u64,
}

// The handle is used by one caller at a time (the C side serializes), and
// `ctx` is only ever passed back to `read`.
unsafe impl Send for Device {}
unsafe impl Sync for Device {}

impl ErrorType for Device {
    type Error = DiskError;
}

impl BlockDevice for Device {
    fn block_size(&self) -> BlockSize {
        match BlockSize::new(BLOCK_SIZE) {
            Some(size) => size,
            None => unreachable!(),
        }
    }

    fn block_count(&self) -> u64 {
        self.blocks
    }

    fn read_blocks(
        &mut self,
        first: BlockIndex,
        buf: &mut [u8],
    ) -> Result<(), hadris_io::Error<DiskError>> {
        let offset =
            first
                .get()
                .checked_mul(u64::from(BLOCK_SIZE))
                .ok_or(hadris_io::Error::new(
                    ErrorKind::InvalidInput,
                    "block out of range",
                ))?;
        // SAFETY: `buf` is valid for `buf.len()` bytes; `read`/`ctx` come from
        // `xnu_rc_apfs_mount`'s caller.
        let errno = unsafe { (self.read)(self.ctx, offset, buf.as_mut_ptr(), buf.len()) };
        if errno != 0 {
            return Err(hadris_io::Error::device(
                DiskError,
                "root device read failed",
            ));
        }
        Ok(())
    }
}

/// The large on-disk structures are boxed so the mount phases below can hand
/// them over as pointers: moving them by value through nested frames would
/// cost several KiB of kernel stack.
struct Mount {
    container: Box<Container<Device>>,
    checkpoint: Box<ContainerSuperblock>,
    volume: Box<VolumeSuperblock>,
    case_insensitive: bool,
    /// The directory listed last: `readdir` asks for one entry per call.
    dir: Option<Cached<OwnedDirectoryEntryRecord>>,
    /// The data stream mapped last: paging maps a file one range per call.
    extents: Option<Cached<FileExtentRecord>>,
}

/// The records of object `id`, kept for the next query on the same object.
struct Cached<T> {
    id: u64,
    records: Vec<T>,
}

/// Mirrors `struct apfsro_time` in bsd/miscfs/apfsro/apfsro.h.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ApfsTime {
    pub sec: i64,
    pub nsec: i64,
}

/// Mirrors `struct apfsro_attr`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ApfsAttr {
    pub ino: u64,
    pub size: u64,
    pub alloc: u64,
    /// `st_mode`: file-type bits | permission bits.
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    /// `st_flags` (APFS `bsd_flags`), e.g. SF_RESTRICTED.
    pub flags: u32,
    pub reserved: u32,
    pub atime: ApfsTime,
    pub mtime: ApfsTime,
    pub ctime: ApfsTime,
    pub btime: ApfsTime,
}

/// Mirrors `struct apfsro_dirent`. `valid == 0` marks the end of the directory.
#[repr(C)]
pub struct ApfsDirent {
    pub ino: u64,
    /// Cookie that continues the walk after this entry.
    pub next_cookie: u64,
    /// File-type bits of `st_mode` only.
    pub mode: u32,
    pub name_len: u32,
    pub valid: u32,
    pub reserved: u32,
    /// NUL-terminated entry name.
    pub name: [u8; NAME_MAX + 1],
}

/// Mirrors `struct apfsro_statfs`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ApfsStatfs {
    pub block_size: u32,
    /// `APFSRO_STATFS_*` bits.
    pub flags: u32,
    pub blocks: u64,
    pub bfree: u64,
    pub files: u64,
}

/// Mirrors `struct apfsro_map`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ApfsMap {
    /// Byte offset in the container image, or `u64::MAX` for a hole.
    pub phys: u64,
    /// Bytes that stay contiguous (or stay a hole) from the queried offset.
    pub run: u64,
}

const _: () = assert!(core::mem::size_of::<ApfsAttr>() == 112);
const _: () = assert!(core::mem::size_of::<ApfsDirent>() == 32 + NAME_MAX + 1);
const _: () = assert!(core::mem::size_of::<ApfsStatfs>() == 32);
const _: () = assert!(core::mem::size_of::<ApfsMap>() == 16);

fn kind_errno(kind: ErrorKind) -> i32 {
    match kind {
        ErrorKind::NotFound => ENOENT,
        ErrorKind::NotADirectory => ENOTDIR,
        ErrorKind::IsADirectory => EISDIR,
        ErrorKind::InvalidInput | ErrorKind::NotRecognized => EINVAL,
        ErrorKind::ReadOnly => EROFS,
        ErrorKind::Unsupported => ENOTSUP,
        ErrorKind::LimitExceeded => EOVERFLOW,
        ErrorKind::NameTooLong => ENAMETOOLONG,
        ErrorKind::FileTooLarge => EFBIG,
        ErrorKind::Symlink => ELOOP,
        ErrorKind::InvalidHandle => ESTALE,
        ErrorKind::Busy => EBUSY,
        ErrorKind::Corrupt => EFTYPE,
        _ => EIO,
    }
}

fn fs_err<E>(error: hadris_fs::Error<E>) -> i32 {
    kind_errno(error.kind())
}

fn time(ns: u64) -> ApfsTime {
    ApfsTime {
        sec: (ns / 1_000_000_000) as i64,
        nsec: (ns % 1_000_000_000) as i64,
    }
}

/// Checks that `extents` (sorted by offset) do not overlap and stay inside
/// the container, as the read and map paths assume.
fn check_extents(extents: &[FileExtentRecord], block_size: u64, block_count: u64) -> Result<(), i32> {
    let mut end = 0;
    for e in extents {
        let e_end = e.logical_address.checked_add(e.length).ok_or(EFTYPE)?;
        if e.logical_address < end {
            return Err(EFTYPE);
        }
        end = e_end;
        if e.physical_block != 0 {
            let blocks = e.length.div_ceil(block_size);
            if e.physical_block
                .checked_add(blocks)
                .is_none_or(|b| b > block_count)
            {
                return Err(EFTYPE);
            }
        }
    }
    Ok(())
}

impl Mount {
    fn inode(&mut self, ino: u64) -> Result<InodeRecord, i32> {
        self.container
            .inode_record(&self.volume, ino)
            .map_err(fs_err)?
            .ok_or(ESTALE)
    }

    /// The entries of directory `dir` without `.` and `..`, in key order.
    fn dir_entries(&mut self, dir: u64) -> Result<&[OwnedDirectoryEntryRecord], i32> {
        if self.dir.as_ref().is_none_or(|c| c.id != dir) {
            self.dir = None;
            let mut records = self
                .container
                .directory_owned_entries(&self.volume, dir)
                .map_err(fs_err)?;
            records.retain(|r| r.name != "." && r.name != "..");
            if records
                .iter()
                .any(|r| r.name.is_empty() || r.name.len() > NAME_MAX)
            {
                return Err(EFTYPE);
            }
            self.dir = Some(Cached { id: dir, records });
        }
        Ok(self.dir.as_ref().map_or(&[], |c| c.records.as_slice()))
    }

    /// The extents of data stream `id` (`InodeRecord::private_id`), sorted
    /// by offset and checked.
    fn extents(&mut self, id: u64) -> Result<&[FileExtentRecord], i32> {
        if self.extents.as_ref().is_none_or(|c| c.id != id) {
            self.extents = None;
            let records = self
                .container
                .file_extents(&self.volume, id)
                .map_err(fs_err)?;
            check_extents(
                &records,
                u64::from(self.checkpoint.block_size),
                self.checkpoint.block_count,
            )?;
            self.extents = Some(Cached { id, records });
        }
        Ok(self.extents.as_ref().map_or(&[], |c| c.records.as_slice()))
    }

    fn symlink_target(&mut self, ino: u64) -> Result<Vec<u8>, i32> {
        match self
            .container
            .symlink_target(&self.volume, ino)
            .map_err(fs_err)?
        {
            Some(target) => Ok(target.into_bytes()),
            None => Err(EFTYPE),
        }
    }

    fn size_of(&mut self, inode: &InodeRecord) -> Result<u64, i32> {
        match inode.mode as u32 & S_IFMT {
            S_IFREG => Ok(stream_size(inode, self.extents(inode.private_id)?)),
            S_IFLNK => Ok(self.symlink_target(inode.id)?.len() as u64),
            _ => Ok(0),
        }
    }

    fn attr(&mut self, inode: &InodeRecord) -> Result<ApfsAttr, i32> {
        let mode = inode.mode as u32;
        let is_dir = mode & S_IFMT == S_IFDIR;
        let alloc = if mode & S_IFMT == S_IFREG {
            self.extents(inode.private_id)?
                .iter()
                .filter(|e| e.physical_block != 0)
                .fold(0u64, |total, e| total.saturating_add(e.length))
        } else {
            0
        };
        let links = i64::from(inode.link_or_child_count);
        // Directories report `.` and the parent entry on top of their children.
        let nlink = if is_dir { links + 2 } else { links.max(1) };
        Ok(ApfsAttr {
            ino: inode.id,
            size: self.size_of(inode)?,
            alloc,
            mode,
            nlink: u32::try_from(nlink).unwrap_or(u32::MAX),
            uid: inode.owner,
            gid: inode.group,
            flags: inode.bsd_flags,
            reserved: 0,
            atime: time(inode.access_time_ns),
            mtime: time(inode.modification_time_ns),
            ctime: time(inode.change_time_ns),
            btime: time(inode.create_time_ns),
        })
    }

    fn dir_inode(&mut self, dir: u64) -> Result<InodeRecord, i32> {
        let inode = self.inode(dir)?;
        if inode.mode as u32 & S_IFMT != S_IFDIR {
            return Err(ENOTDIR);
        }
        Ok(inode)
    }
}

// Each mount phase is its own non-inlined function so that its (large)
// temporaries live only for the duration of the phase; the caller keeps just
// pointers. The deepest phase is `open_container`, which runs hadris's
// `Container::try_open` and its 4 KiB header buffer.

#[inline(never)]
fn open_container(device: Device) -> Result<Box<Container<Device>>, i32> {
    let container = Container::try_open(device).map_err(|e| fs_err(e.into_error()))?;
    Ok(Box::new(container))
}

#[inline(never)]
fn latest_checkpoint(container: &mut Container<Device>) -> Result<Box<ContainerSuperblock>, i32> {
    Ok(Box::new(container.latest_superblock().map_err(fs_err)?))
}

/// The container's sole volume.
#[inline(never)]
fn sole_volume(
    container: &mut Container<Device>,
    checkpoint: &ContainerSuperblock,
) -> Result<Box<VolumeSuperblock>, i32> {
    let mut volumes = container.volume_superblocks(checkpoint).map_err(fs_err)?;
    if volumes.len() != 1 {
        return Err(if volumes.is_empty() { ENOENT } else { EINVAL });
    }
    let volume = Box::new(volumes.swap_remove(0));
    if checkpoint.flags & SB_FLAG_ENCRYPTED != 0 && volume.flags & APFS_FS_UNENCRYPTED == 0 {
        return Err(ENOTSUP);
    }
    Ok(volume)
}

#[inline(never)]
fn mount_image(device: Device) -> Result<Box<Mount>, i32> {
    let mut container = open_container(device)?;
    let checkpoint = latest_checkpoint(&mut container)?;
    let volume = sole_volume(&mut container, &checkpoint)?;
    let mut m = Box::new(Mount {
        container,
        checkpoint,
        case_insensitive: volume.is_case_insensitive(),
        volume,
        dir: None,
        extents: None,
    });
    match m.inode(ROOT_INO) {
        Ok(root) if root.mode as u32 & S_IFMT == S_IFDIR => Ok(m),
        Ok(_) | Err(ESTALE) => Err(EFTYPE),
        Err(errno) => Err(errno),
    }
}

/// Mounts the APFS container on the root device, writing a handle to `*out`.
///
/// `read` fetches device bytes (see `ReadFn`); `ctx` is passed back to it and
/// both must stay valid until `xnu_rc_apfs_unmount`. `len` is the device size
/// in bytes.
///
/// # Safety
/// `read` must honor the `ReadFn` contract and `out` must be writable.
#[no_mangle]
pub unsafe extern "C" fn xnu_rc_apfs_mount(
    read: ReadFn,
    ctx: *mut c_void,
    len: u64,
    out: *mut *mut c_void,
) -> i32 {
    if out.is_null() {
        return EINVAL;
    }
    let device = Device {
        // The callback arrives signed on arm64e (see `ptrauth`).
        read: crate::ptrauth::auth(read),
        ctx,
        blocks: len / u64::from(BLOCK_SIZE),
    };
    match mount_image(device) {
        Ok(m) => {
            *out = Box::into_raw(m).cast();
            0
        }
        Err(errno) => errno,
    }
}

/// Releases a handle returned by `xnu_rc_apfs_mount`.
///
/// # Safety
/// `handle` must come from `xnu_rc_apfs_mount` and not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn xnu_rc_apfs_unmount(handle: *mut c_void) {
    if !handle.is_null() {
        drop(Box::from_raw(handle.cast::<Mount>()));
    }
}

/// Root directory inode number.
#[no_mangle]
pub extern "C" fn xnu_rc_apfs_root_ino() -> u64 {
    ROOT_INO
}

unsafe fn mount<'a>(handle: *mut c_void) -> &'a mut Mount {
    &mut *handle.cast::<Mount>()
}

/// Volume geometry and object counts.
///
/// # Safety
/// `handle` must be a live mount handle and `out` writable.
#[no_mangle]
pub unsafe extern "C" fn xnu_rc_apfs_statfs(handle: *mut c_void, out: *mut ApfsStatfs) -> i32 {
    let m = mount(handle);
    let block_size = m.checkpoint.block_size;
    // The space manager summary is advisory; report a full volume without it.
    let (blocks, bfree) = match m.container.space_manager_summary(&m.checkpoint) {
        Ok(s) if s.main_device.free_count <= s.main_device.block_count => {
            (s.main_device.block_count, s.main_device.free_count)
        }
        _ => (m.checkpoint.block_count, 0),
    };
    let v = &m.volume;
    ptr::write(
        out,
        ApfsStatfs {
            block_size,
            flags: if m.case_insensitive {
                STATFS_CASE_INSENSITIVE
            } else {
                0
            },
            blocks,
            bfree,
            files: v
                .number_files
                .saturating_add(v.number_directories)
                .saturating_add(v.number_symlinks),
        },
    );
    0
}

/// Attributes of inode `ino`.
///
/// # Safety
/// `handle` must be a live mount handle and `out` writable.
#[no_mangle]
pub unsafe extern "C" fn xnu_rc_apfs_getattr(
    handle: *mut c_void,
    ino: u64,
    out: *mut ApfsAttr,
) -> i32 {
    let m = mount(handle);
    match m.inode(ino).and_then(|i| m.attr(&i)) {
        Ok(attr) => {
            ptr::write(out, attr);
            0
        }
        Err(errno) => errno,
    }
}

/// Resolves one path component `name` inside directory `dir`.
///
/// # Safety
/// `handle` must be a live mount handle, `name` valid for `name_len` bytes and
/// `out` writable.
#[no_mangle]
pub unsafe extern "C" fn xnu_rc_apfs_lookup(
    handle: *mut c_void,
    dir: u64,
    name: *const u8,
    name_len: usize,
    out: *mut ApfsAttr,
) -> i32 {
    if name.is_null() || name_len == 0 {
        return EINVAL;
    }
    let m = mount(handle);
    if let Err(errno) = m.dir_inode(dir) {
        return errno;
    }
    if name_len > NAME_MAX {
        return ENAMETOOLONG;
    }
    let Ok(wanted) = core::str::from_utf8(slice::from_raw_parts(name, name_len)) else {
        return ENOENT;
    };
    let comparison = m.volume.name_comparison();
    let entries = match m.dir_entries(dir) {
        Ok(entries) => entries,
        Err(errno) => return errno,
    };
    // An exact name wins over one that only matches after folding.
    let found = entries
        .iter()
        .find(|e| e.name == wanted)
        .or_else(|| entries.iter().find(|e| comparison.matches(&e.name, wanted)));
    let Some(file_id) = found.map(|e| e.file_id) else {
        return ENOENT;
    };
    match m.inode(file_id) {
        Ok(inode) => match m.attr(&inode) {
            Ok(attr) => {
                ptr::write(out, attr);
                0
            }
            Err(errno) => errno,
        },
        // The entry names an inode the volume does not have.
        Err(ESTALE) => EFTYPE,
        Err(errno) => errno,
    }
}

/// Parent directory of directory `dir` (the root is its own parent).
///
/// # Safety
/// `handle` must be a live mount handle and `out` writable.
#[no_mangle]
pub unsafe extern "C" fn xnu_rc_apfs_parent(handle: *mut c_void, dir: u64, out: *mut u64) -> i32 {
    let m = mount(handle);
    let inode = match m.dir_inode(dir) {
        Ok(i) => i,
        Err(errno) => return errno,
    };
    let parent = if dir == ROOT_INO {
        ROOT_INO
    } else {
        inode.parent_id
    };
    match m.dir_inode(parent) {
        Ok(_) => {
            *out = parent;
            0
        }
        Err(ESTALE | ENOTDIR) => EFTYPE,
        Err(errno) => errno,
    }
}

/// Reads the directory entry at `cookie` (0 starts the directory). On success
/// `out.valid` is 1 and `out.next_cookie` continues the walk; `out.valid` is 0
/// past the last entry.
///
/// # Safety
/// `handle` must be a live mount handle and `out` writable.
#[no_mangle]
pub unsafe extern "C" fn xnu_rc_apfs_readdir(
    handle: *mut c_void,
    dir: u64,
    cookie: u64,
    out: *mut ApfsDirent,
) -> i32 {
    let m = mount(handle);
    if let Err(errno) = m.dir_inode(dir) {
        return errno;
    }
    ptr::addr_of_mut!((*out).valid).write(0);
    let entries = match m.dir_entries(dir) {
        Ok(entries) => entries,
        Err(errno) => return errno,
    };
    let Some(entry) = usize::try_from(cookie).ok().and_then(|i| entries.get(i)) else {
        return 0;
    };
    let name = entry.name.as_bytes();
    ptr::addr_of_mut!((*out).ino).write(entry.file_id);
    ptr::addr_of_mut!((*out).next_cookie).write(cookie + 1);
    // The record carries the file type (DTTOIF: a DT_* value is the S_IFMT
    // bits shifted down by 12).
    ptr::addr_of_mut!((*out).mode).write((u32::from(entry.file_type()) << 12) & S_IFMT);
    ptr::addr_of_mut!((*out).name_len).write(name.len() as u32);
    ptr::addr_of_mut!((*out).reserved).write(0);
    let dst = ptr::addr_of_mut!((*out).name).cast::<u8>();
    ptr::copy_nonoverlapping(name.as_ptr(), dst, name.len());
    dst.add(name.len()).write(0);
    ptr::addr_of_mut!((*out).valid).write(1);
    0
}

/// Copies the symlink target of `ino` (no NUL) into `buf`, storing its length
/// in `*out_len`.
///
/// # Safety
/// `handle` must be a live mount handle, `buf` valid for `buf_len` writable
/// bytes and `out_len` writable.
#[no_mangle]
pub unsafe extern "C" fn xnu_rc_apfs_readlink(
    handle: *mut c_void,
    ino: u64,
    buf: *mut u8,
    buf_len: usize,
    out_len: *mut usize,
) -> i32 {
    let m = mount(handle);
    match m.inode(ino) {
        Ok(i) if i.mode as u32 & S_IFMT == S_IFLNK => {}
        Ok(_) => return EINVAL,
        Err(errno) => return errno,
    }
    let target = match m.symlink_target(ino) {
        Ok(t) => t,
        Err(errno) => return errno,
    };
    if target.len() > buf_len {
        return ENAMETOOLONG;
    }
    ptr::copy_nonoverlapping(target.as_ptr(), buf, target.len());
    *out_len = target.len();
    0
}

fn regular_file(m: &mut Mount, ino: u64) -> Result<InodeRecord, i32> {
    let inode = m.inode(ino)?;
    match inode.mode as u32 & S_IFMT {
        S_IFREG => {}
        S_IFDIR => return Err(EISDIR),
        _ => return Err(EINVAL),
    }
    if inode.is_compressed() {
        return Err(ENOTSUP);
    }
    Ok(inode)
}

/// Reads up to `len` bytes of file `ino` at `offset`. Short only at end of
/// file; holes read as zeroes. The count is stored in `*out_read`.
///
/// # Safety
/// `handle` must be a live mount handle, `buf` valid for `len` writable bytes
/// and `out_read` writable.
#[no_mangle]
pub unsafe extern "C" fn xnu_rc_apfs_read(
    handle: *mut c_void,
    ino: u64,
    offset: u64,
    buf: *mut u8,
    len: usize,
    out_read: *mut usize,
) -> i32 {
    let m = mount(handle);
    let inode = match regular_file(m, ino) {
        Ok(i) => i,
        Err(errno) => return errno,
    };
    if len == 0 {
        *out_read = 0;
        return 0;
    }
    if let Err(errno) = m.extents(inode.private_id) {
        return errno;
    }
    let Mount {
        container,
        volume,
        extents,
        ..
    } = m;
    let extents = extents.as_ref().map_or(&[][..], |c| c.records.as_slice());
    let size = stream_size(&inode, extents);
    let dst = slice::from_raw_parts_mut(buf, len);
    match container.read_volume_extents_at(volume, extents, size, offset, dst) {
        Ok(n) => {
            *out_read = n;
            0
        }
        Err(error) => fs_err(error),
    }
}

/// Locates `offset` in a file of `size` bytes whose extents (sorted by offset,
/// non-overlapping) are `extents`. Returns the container byte offset and the
/// contiguous run, or a hole.
fn map_extents(
    extents: &[FileExtentRecord],
    size: u64,
    block_size: u64,
    offset: u64,
) -> Result<ApfsMap, i32> {
    if offset >= size {
        return Ok(ApfsMap { phys: HOLE, run: 0 });
    }
    // First extent that ends after `offset`.
    let at = extents.partition_point(|e| e.logical_address + e.length <= offset);
    match extents.get(at) {
        Some(e) if e.logical_address <= offset => {
            if e.cryptography_id != 0 {
                return Err(ENOTSUP);
            }
            let within = offset - e.logical_address;
            let run = e.length - within;
            if e.physical_block == 0 {
                return Ok(ApfsMap { phys: HOLE, run });
            }
            let base = e.physical_block.checked_mul(block_size).ok_or(EFTYPE)?;
            Ok(ApfsMap {
                phys: base + within,
                run,
            })
        }
        // `offset` falls in a gap before the next extent (or the file's tail).
        next => {
            let end = next.map_or(size, |e| e.logical_address.min(size));
            Ok(ApfsMap {
                phys: HOLE,
                run: end - offset,
            })
        }
    }
}

/// Maps file offset `offset` of `ino` to its location in the container image.
/// `out.phys` is a byte offset into the image (`u64::MAX` for a hole) and
/// `out.run` the length that stays contiguous from `offset`, up to the end of
/// the file's data.
///
/// # Safety
/// `handle` must be a live mount handle and `out` writable.
#[no_mangle]
pub unsafe extern "C" fn xnu_rc_apfs_map(
    handle: *mut c_void,
    ino: u64,
    offset: u64,
    out: *mut ApfsMap,
) -> i32 {
    let m = mount(handle);
    let inode = match regular_file(m, ino) {
        Ok(i) => i,
        Err(errno) => return errno,
    };
    let block_size = u64::from(m.checkpoint.block_size);
    let extents = match m.extents(inode.private_id) {
        Ok(extents) => extents,
        Err(errno) => return errno,
    };
    let size = stream_size(&inode, extents);
    match map_extents(extents, size, block_size, offset) {
        Ok(map) => {
            ptr::write(out, map);
            0
        }
        Err(errno) => errno,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BS: u64 = 4096;

    /// Builds an extent through the parser, as the volume index does.
    fn extent(logical: u64, length: u64, block: u64, crypto: u64) -> FileExtentRecord {
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&((8u64 << 60) | 17).to_le_bytes());
        key[8..].copy_from_slice(&logical.to_le_bytes());
        let mut value = [0u8; 24];
        value[..8].copy_from_slice(&length.to_le_bytes());
        value[8..16].copy_from_slice(&block.to_le_bytes());
        value[16..].copy_from_slice(&crypto.to_le_bytes());
        FileExtentRecord::parse(&key, &value).unwrap()
    }

    fn map(extents: &[FileExtentRecord], size: u64, offset: u64) -> (u64, u64) {
        let m = map_extents(extents, size, BS, offset).unwrap();
        (m.phys, m.run)
    }

    #[test]
    fn single_extent() {
        let e = [extent(0, 8192, 10, 0)];
        assert_eq!(map(&e, 5000, 0), (10 * BS, 8192));
        assert_eq!(map(&e, 5000, 4096), (11 * BS, 4096));
        assert_eq!(map(&e, 5000, 4999), (11 * BS + 903, 3193));
        assert_eq!(map(&e, 5000, 5000), (HOLE, 0));
        assert_eq!(map(&e, 5000, u64::MAX), (HOLE, 0));
    }

    #[test]
    fn extents_are_not_merged_and_gaps_are_holes() {
        // [0, 4096) at block 7, hole [4096, 12288), [12288, 16384) at block 3.
        let e = [extent(0, 4096, 7, 0), extent(12288, 4096, 3, 0)];
        assert_eq!(map(&e, 16384, 0), (7 * BS, 4096));
        assert_eq!(map(&e, 16384, 4096), (HOLE, 8192));
        assert_eq!(map(&e, 16384, 8192), (HOLE, 4096));
        assert_eq!(map(&e, 16384, 12288), (3 * BS, 4096));
        assert_eq!(map(&e, 16384, 16383), (3 * BS + 4095, 1));
    }

    #[test]
    fn trailing_hole_stops_at_end_of_file() {
        let e = [extent(0, 4096, 7, 0)];
        assert_eq!(map(&e, 10000, 4096), (HOLE, 10000 - 4096));
        assert_eq!(map(&[], 100, 0), (HOLE, 100));
    }

    #[test]
    fn explicit_sparse_extent_is_a_hole() {
        let e = [extent(0, 8192, 0, 0), extent(8192, 4096, 5, 0)];
        assert_eq!(map(&e, 12288, 4096), (HOLE, 4096));
        assert_eq!(map(&e, 12288, 8192), (5 * BS, 4096));
    }

    #[test]
    fn encrypted_extents_are_refused() {
        let e = [extent(0, 4096, 7, 9)];
        assert_eq!(map_extents(&e, 4096, BS, 0).err(), Some(ENOTSUP));
    }

    #[test]
    fn huge_block_numbers_do_not_overflow() {
        let e = [extent(0, 4096, u64::MAX / 2, 0)];
        assert_eq!(map_extents(&e, 4096, BS, 0).err(), Some(EFTYPE));
    }
}
