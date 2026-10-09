use mkapfs_lib::{ImageDevice, Options, build};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
usage: mkapfs --size <bytes|NK|NM|NG> --label <name> -o <out.img> [options] <dir>

Packs <dir> into a single-volume APFS container image (block size 4096).

options:
  --size <n>          container size; a multiple of 4096, optional K/M/G suffix (powers of 1024)
  --label <name>      volume name
  -o, --output <path> output image (created/truncated; sparse)
  --timestamp <secs>  timestamp for all inodes (default: $SOURCE_DATE_EPOCH, else 0)
  --root-mode <octal> permission bits of the root directory (default 755)
  --uid <n>           owner of every inode (default 0)
  --gid <n>           group of every inode (default 0)
  --bsd-flags <hex>   BSD file flags (st_flags) of every inode, e.g. 80000 for SF_RESTRICTED (default 0)
  -h, --help          show this help
";

fn parse_size(s: &str) -> Result<u64, String> {
    let (num, mult) = match s.chars().last() {
        Some('K') | Some('k') => (&s[..s.len() - 1], 1u64 << 10),
        Some('M') | Some('m') => (&s[..s.len() - 1], 1 << 20),
        Some('G') | Some('g') => (&s[..s.len() - 1], 1 << 30),
        _ => (s, 1),
    };
    let n: u64 = num.parse().map_err(|_| format!("invalid size {s:?}"))?;
    n.checked_mul(mult)
        .ok_or_else(|| format!("size {s:?} overflows"))
}

struct Args {
    size: u64,
    label: String,
    out: PathBuf,
    dir: PathBuf,
    timestamp: u64,
    root_mode: u16,
    uid: u32,
    gid: u32,
    bsd_flags: u32,
}

fn parse_args() -> Result<Args, String> {
    let mut size = None;
    let mut label = None;
    let mut out = None;
    let mut dir = None;
    let mut timestamp = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut root_mode = 0o755u16;
    let (mut uid, mut gid) = (0u32, 0u32);
    let mut bsd_flags = 0u32;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let mut value = |name: &str| it.next().ok_or_else(|| format!("{name} needs a value"));
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "--size" => size = Some(parse_size(&value("--size")?)?),
            "--label" => label = Some(value("--label")?),
            "-o" | "--output" => out = Some(PathBuf::from(value("-o")?)),
            "--timestamp" => {
                timestamp = value("--timestamp")?
                    .parse()
                    .map_err(|_| "invalid --timestamp")?
            }
            "--root-mode" => {
                root_mode = u16::from_str_radix(&value("--root-mode")?, 8)
                    .map_err(|_| "invalid --root-mode")?
            }
            "--uid" => uid = value("--uid")?.parse().map_err(|_| "invalid --uid")?,
            "--gid" => gid = value("--gid")?.parse().map_err(|_| "invalid --gid")?,
            "--bsd-flags" => {
                bsd_flags = u32::from_str_radix(&value("--bsd-flags")?, 16)
                    .map_err(|_| "invalid --bsd-flags")?
            }
            s if s.starts_with('-') => return Err(format!("unknown option {s}")),
            _ => {
                if dir.replace(PathBuf::from(&a)).is_some() {
                    return Err("exactly one source directory expected".into());
                }
            }
        }
    }
    Ok(Args {
        size: size.ok_or("--size is required")?,
        label: label.ok_or("--label is required")?,
        out: out.ok_or("-o is required")?,
        dir: dir.ok_or("source directory is required")?,
        timestamp,
        root_mode,
        uid,
        gid,
        bsd_flags,
    })
}

fn run() -> Result<(), String> {
    let args = parse_args().map_err(|e| format!("{e}\n\n{USAGE}"))?;
    let options = Options {
        size: args.size,
        label: args.label,
        timestamp: i64::try_from(args.timestamp).map_err(|_| "--timestamp too large")?,
        root_mode: args.root_mode,
        uid: args.uid,
        gid: args.gid,
        bsd_flags: args.bsd_flags,
    };
    let mut dev = ImageDevice::create(&args.out, args.size).map_err(|e| e.to_string())?;
    let (formatted, stats) = build(&mut dev, &args.dir, &options).map_err(|e| e.to_string())?;
    eprintln!(
        "mkapfs: {}: {} files, {} dirs, {} symlinks; {} blocks",
        args.out.display(),
        stats.files,
        stats.dirs,
        stats.symlinks,
        formatted.block_count,
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mkapfs: {e}");
            ExitCode::FAILURE
        }
    }
}
