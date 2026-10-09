//! Round-trip test: pack a host tree with mkapfs and read it back through the
//! hadris-apfs sync reader, comparing against the input tree.

use hadris_apfs::sync::ApfsFs;
#[allow(unused_imports)]
// needed by hadris-apfs 3.0.0-rc.1; later revisions have inherent methods
use hadris_fs::sync::FileSystem;
use hadris_fs::{DirCursor, FileType, MountOptions, Name, NodeId, OpenMode};
use hadris_storage::{BlockSize, MemDevice};
use mkapfs_lib::{build, Options};
use std::path::Path;

const BLOCK: usize = 4096;
const SIZE: u64 = 16 << 20;

type Fs = ApfsFs<MemDevice<Vec<u8>>>;

/// Deterministic pseudo-random bytes.
fn pattern(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn options() -> Options {
    Options {
        size: SIZE,
        label: String::from("roundtrip"),
        timestamp: 1_700_000_000,
        root_mode: 0o755,
        uid: 501,
        gid: 20,
        bsd_flags: 0x80000,
    }
}

/// Builds the source tree under `dir`.
fn source_tree(dir: &Path) {
    let docs = dir.join("docs");
    let sub = docs.join("sub");
    std::fs::create_dir_all(&sub).unwrap();
    for (name, len) in [
        ("empty", 0),
        ("one", 1),
        ("block", BLOCK),
        ("block-plus", BLOCK + 1),
        ("many", BLOCK * 9 + 77),
    ] {
        std::fs::write(docs.join(name), pattern(len as u64, len)).unwrap();
    }
    std::fs::write(sub.join("deep"), b"nested\n").unwrap();
    std::fs::write(dir.join("motd"), b"hello\n").unwrap();
    std::os::unix::fs::symlink("docs/one", dir.join("latest")).unwrap();

    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.join("motd"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&docs, std::fs::Permissions::from_mode(0o750)).unwrap();
}

/// Packs `dir` and mounts the result.
fn pack(dir: &Path) -> Fs {
    let mut dev = MemDevice::new(vec![0_u8; SIZE as usize], BlockSize::new(BLOCK as u32).unwrap());
    build(&mut dev, dir, &options()).unwrap();
    let device = dev.into_inner();
    ApfsFs::mount(
        MemDevice::new(device, BlockSize::new(BLOCK as u32).unwrap()),
        MountOptions::new(),
    )
    .unwrap()
}

fn read_all(fs: &mut Fs, node: NodeId, len: u64) -> Vec<u8> {
    fs.open(node, OpenMode::Read).unwrap();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 10_000]; // deliberately not a block multiple
    loop {
        let n = fs.read(node, out.len() as u64, &mut buf).unwrap();
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    fs.close(node).unwrap();
    assert_eq!(out.len() as u64, len);
    out
}

fn host_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn check_dir(fs: &mut Fs, dir_node: NodeId, host: &Path, files: &mut u64) {
    let mut listed = Vec::new();
    let mut cursor = DirCursor::START;
    while let Some(entry) = fs.readdir(dir_node, cursor).unwrap() {
        cursor = entry.next_cursor();
        listed.push(String::from_utf8(entry.name().as_bytes().to_vec()).unwrap());
    }
    listed.sort();
    assert_eq!(listed, host_names(host), "{}: listing", host.display());

    for name in listed {
        let path = host.join(&name);
        let meta = std::fs::symlink_metadata(&path).unwrap();
        let id = fs.lookup(dir_node, Name::new(name.as_str())).unwrap();
        let stat = fs.stat(id).unwrap();
        let mode = (std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o7777) as u32;
        assert_eq!(stat.permissions().bits(), mode, "{name}: mode");
        assert_eq!(stat.owner().unwrap().uid(), 501, "{name}: owner");
        assert_eq!(stat.owner().unwrap().gid(), 20, "{name}: group");

        if meta.is_dir() {
            assert_eq!(fs.parent(id).unwrap(), dir_node, "{name}: parent");
            assert_eq!(stat.file_type(), FileType::Dir, "{name}");
            check_dir(fs, id, &path, files);
        } else if meta.file_type().is_symlink() {
            assert_eq!(stat.file_type(), FileType::Symlink, "{name}");
            let mut buf = vec![0u8; 4096];
            let target = std::fs::read_link(&path).unwrap();
            assert_eq!(
                fs.readlink(id, &mut buf).unwrap(),
                target.as_os_str().as_encoded_bytes(),
                "{name}: target"
            );
        } else {
            *files += 1;
            let data = std::fs::read(&path).unwrap();
            assert_eq!(stat.file_type(), FileType::File, "{name}");
            assert_eq!(stat.len(), data.len() as u64, "{name}: len");
            assert_eq!(
                stat.allocated(),
                data.len().div_ceil(BLOCK) as u64 * BLOCK as u64,
                "{name}: one contiguous extent"
            );
            assert!(read_all(fs, id, data.len() as u64) == data, "{name}: content");
            if data.len() > 5000 {
                let mut buf = [0u8; 300];
                assert_eq!(fs.read(id, 4000, &mut buf).unwrap(), 300);
                assert_eq!(&buf[..], &data[4000..4300], "{name}: random read");
            }
        }
    }
}

#[test]
fn a_host_tree_round_trips_through_the_hadris_reader() {
    let dir = std::env::temp_dir().join(format!("mkapfs-roundtrip-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    source_tree(&dir);

    let mut fs = pack(&dir);
    let root = fs.root();
    let mut files = 0;
    check_dir(&mut fs, root, &dir, &mut files);
    assert_eq!(files, 7, "checked file count");
    assert_eq!(
        fs.lookup(root, Name::new("missing")).unwrap_err().kind(),
        hadris_fs::ErrorKind::NotFound
    );

    std::fs::remove_dir_all(&dir).unwrap();
}
