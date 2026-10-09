//! mkapfs: packs a host directory tree into a single-volume APFS container.
//!
//! Directories, regular files, symlinks, permission bits, owners and BSD file
//! flags are stored by the `hadris-apfs` writer, which lays out the container
//! the same way this tool used to: block 0 and the checkpoint areas, then the
//! space manager, object maps and trees, with every file in one contiguous
//! extent and everything at transaction 1. The output is meant to be consumed
//! read-only (for example as a boot root), so the volume holds no snapshots,
//! compression or clones.
//!
//! File contents are streamed from the host as the container is written, so a
//! tree larger than memory packs without being held in memory.

mod device;
mod scan;

pub use device::ImageDevice;
pub use scan::scan_dir;

use std::fmt;

use hadris_apfs::sync::format;
use hadris_apfs::{ApfsNode, ApfsOptions, Formatted};
use hadris_fs::{DateTime, ErrorKind};
use hadris_storage::sync::BlockDevice;

/// How many inodes of each kind a scan found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub files: u64,
    pub dirs: u64,
    pub symlinks: u64,
}

/// Tool options for one container.
pub struct Options {
    /// Container size in bytes; a multiple of 4096.
    pub size: u64,
    /// Volume name.
    pub label: String,
    /// Timestamp of every inode, in seconds since the Unix epoch.
    pub timestamp: i64,
    /// Permission bits of the root directory.
    pub root_mode: u16,
    /// Owner of every inode.
    pub uid: u32,
    /// Group of every inode.
    pub gid: u32,
    /// BSD file flags (`st_flags`) of every inode.
    pub bsd_flags: u32,
}

impl Options {
    /// The writer's options for a scanned `root`.
    fn apfs(&self, root: ApfsNode) -> Result<ApfsOptions, Error> {
        let time = DateTime::from_unix_seconds(self.timestamp)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "timestamp out of range"))?;
        Ok(ApfsOptions::new()
            .with_label(&self.label)
            .with_size(self.size)
            .with_time(time)
            .with_root(root))
    }
}

/// What packing a tree failed with: a host error or a rejected container.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl Error {
    fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// The error kind, matching `hadris_io::ErrorKind`.
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::new(ErrorKind::Io, err.to_string())
    }
}

/// Packs `dir` into `dev` as a single-volume APFS container.
///
/// The device must hold at least [`Options::size`] bytes. Files are read from
/// `dir` as the container is written.
pub fn build<D: BlockDevice>(
    dev: &mut D,
    dir: &std::path::Path,
    options: &Options,
) -> Result<(Formatted, Stats), Error>
where
    D::Error: fmt::Display,
{
    let (root, stats) = scan_dir(dir, options)?;
    let apfs = options.apfs(root)?;
    let formatted = format(dev, &apfs).map_err(|err| match err.device_error() {
        Some(device) => Error::new(err.kind(), device.to_string()),
        None => Error::new(err.kind(), err.message()),
    })?;
    Ok((formatted, stats))
}
