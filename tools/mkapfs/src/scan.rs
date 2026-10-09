//! Host directory tree reader.
//!
//! Walks `dir` and builds the `hadris-apfs` node tree of everything it holds.
//! Regular files are not read here: each becomes a [`HostFile`] source that
//! the writer reads chunk by chunk as it lays the container out.

use std::fs;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use hadris_apfs::{ApfsNode, FileSource};
use hadris_fs::ErrorKind;

use crate::{Error, Options, Stats};

/// Longest entry name APFS stores.
const MAX_NAME: usize = 255;
/// Longest symlink target stored inline.
const MAX_SYMLINK: usize = 1024;

/// A regular file opened on demand so its bytes are never all in memory.
#[derive(Debug)]
struct HostFile {
    path: PathBuf,
    len: u64,
}

impl FileSource for HostFile {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, ErrorKind> {
        let file = fs::File::open(&self.path).map_err(|_| ErrorKind::Io)?;
        let count = buf.len().min(self.len.saturating_sub(offset) as usize);
        file.read_at(&mut buf[..count], offset)
            .map_err(|_| ErrorKind::Io)
    }
}

/// Reads `dir` into the node tree the writer packs, with how many inodes of
/// each kind it holds.
pub fn scan_dir(dir: &Path, options: &Options) -> Result<(ApfsNode, Stats), Error> {
    let meta = fs::metadata(dir).map_err(|err| at(dir, err))?;
    if !meta.is_dir() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("{} is not a directory", dir.display()),
        ));
    }
    let mut stats = Stats::default();
    let mut root = ApfsNode::directory();
    for (name, node) in children(dir, options, &mut stats)? {
        root.add(&name, node)
            .map_err(|kind| rejected(dir.join(&name), kind))?;
    }
    let root = root
        .with_mode(options.root_mode)
        .with_owner(options.uid, options.gid)
        .with_flags(options.bsd_flags);
    Ok((root, stats))
}

fn children(
    dir: &Path,
    options: &Options,
    stats: &mut Stats,
) -> Result<Vec<(String, ApfsNode)>, Error> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).map_err(|err| at(dir, err))? {
        let entry = entry.map_err(|err| at(dir, err))?;
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|name| at(dir, format!("entry name is not UTF-8: {name:?}")))?;
        let meta = fs::symlink_metadata(&path).map_err(|err| at(&path, err))?;
        let node = node_for(&path, &meta, options, stats)?;
        out.push((name, node));
    }
    Ok(out)
}

fn node_for(
    path: &Path,
    meta: &fs::Metadata,
    options: &Options,
    stats: &mut Stats,
) -> Result<ApfsNode, Error> {
    let kind = meta.file_type();
    let mode = (meta.permissions().mode() & 0o7777) as u16;
    let node = if kind.is_dir() {
        stats.dirs += 1;
        let mut dir = ApfsNode::directory();
        for (name, node) in children(path, options, stats)? {
            dir.add(&name, node)
                .map_err(|kind| rejected(path.join(&name), kind))?;
        }
        dir
    } else if kind.is_symlink() {
        stats.symlinks += 1;
        let target = fs::read_link(path).map_err(|err| at(path, err))?;
        let Some(target) = target.to_str() else {
            return Err(at(path, "symlink target is not UTF-8"));
        };
        if target.is_empty() || target.len() > MAX_SYMLINK || target.contains('\0') {
            return Err(at(
                path,
                format!("symlink target length {} unsupported", target.len()),
            ));
        }
        ApfsNode::symlink(target)
    } else if kind.is_file() {
        stats.files += 1;
        ApfsNode::file_from(HostFile {
            path: path.to_path_buf(),
            len: meta.len(),
        })
    } else {
        return Err(at(
            path,
            "unsupported file type (only dirs, regular files and symlinks)",
        ));
    };
    Ok(node
        .with_mode(mode)
        .with_owner(options.uid, options.gid)
        .with_flags(options.bsd_flags))
}

fn at(path: &Path, message: impl std::fmt::Display) -> Error {
    Error::new(ErrorKind::Io, format!("{}: {message}", path.display()))
}

fn rejected(path: PathBuf, kind: ErrorKind) -> Error {
    let message = match kind {
        ErrorKind::NameTooLong => format!("entry name too long (> {MAX_NAME} bytes)"),
        ErrorKind::AlreadyExists => "two names compare equal".to_string(),
        other => format!("{other:?}"),
    };
    Error::new(kind, format!("{}: {message}", path.display()))
}
