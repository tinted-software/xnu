// SPDX-License-Identifier: MIT
// migcom — Mach Interface Generator compiler (Rust rewrite)
//
// This binary reads a pre-processed .defs file from stdin (the C preprocessor
// is invoked by the `mig` shell wrapper, exactly as in the original) and
// writes the user-side header, user stub, and server stub to the paths
// specified via command-line flags.

mod ast;
mod codegen;
mod diag;
mod global;
mod lexer;
mod lower;
mod parser;
mod routine;
mod types;

use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::process;

use winnow_args::Args;

use diag::Diag;
use global::{Options, MIG_VERSION};

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

/// Mach Interface Generator: the `mig` driver and the `migcom` compiler in
/// one binary.
///
/// Without an input file this is `migcom`: pre-processed `.defs` arrives on
/// stdin and the `-user`/`-server`/`-header`/… outputs are written out. With
/// a `.defs` file this is `mig`: the file is pre-processed (extra words such
/// as `-D`/`-I` go straight to the pre-processor) and piped into `migcom`.
///
/// Single-dash multi-letter flags (`-user`, `-sheader`, `-maxonstack`, …)
/// need `long_only` (GNU `getopt_long_only`): a full-word match wins over a
/// short bundle, so `-server` is the server flag rather than `-s` + `erver`.
/// Case-swapped toggle pairs (`-q`/`-Q`, `-v`/`-V`, …) are two fields with
/// mutual `overrides`, so the last spelling on the command line wins exactly
/// like the original hand-rolled parser.
#[derive(Args, Debug)]
#[arg(name = "mig", long_only, unknown_flags = "value")]
struct MigArgs {
    /// Suppress warnings (`-Q` negates; last wins).
    #[arg(short = 'q', overrides = "-Q")]
    quiet: bool,
    #[arg(short = 'Q', overrides = "-q", hide)]
    no_quiet: bool,
    /// Be verbose (`-V` negates; last wins).
    #[arg(short = 'v', overrides = "-V")]
    verbose: bool,
    #[arg(short = 'V', overrides = "-v", hide)]
    no_verbose: bool,
    #[arg(short = 'r', overrides = "-R", hide)]
    msg_rpc_on: bool,
    /// Use mach_msg() instead of msg_rpc() (`-r` negates; last wins).
    #[arg(short = 'R', overrides = "-r")]
    no_msg_rpc: bool,
    /// Log events (`-l` negates; last wins).
    #[arg(short = 'L', overrides = "-l")]
    event_logger: bool,
    #[arg(short = 'l', overrides = "-L", hide)]
    no_event_logger: bool,
    #[arg(short = 'k', overrides = "-K", hide)]
    ansi_on: bool,
    /// Emit pre-ANSI (K&R) C (`-k` negates; last wins).
    #[arg(short = 'K', overrides = "-k")]
    no_ansi_c: bool,
    /// Check NDR format (`-N` negates; last wins).
    #[arg(short = 'n', overrides = "-N")]
    check_ndr: bool,
    #[arg(short = 'N', overrides = "-n", hide)]
    no_check_ndr: bool,
    /// Generate the symbol table (`-S` negates; last wins).
    #[arg(short = 's', overrides = "-S")]
    sym_tab: bool,
    #[arg(short = 'S', overrides = "-s", hide)]
    no_sym_tab: bool,
    /// Use the RPC trap, testing it too (`-T` disables use; last wins).
    #[arg(short = 't', overrides = "-T")]
    trap_test: bool,
    #[arg(short = 'T', overrides = "-t", hide)]
    no_trap: bool,
    /// Short-circuit messages (`-X` negates; last wins).
    #[arg(short = 'x', overrides = "-X")]
    short_circuit: bool,
    #[arg(short = 'X', overrides = "-x", hide)]
    no_short_circuit: bool,
    /// Annotate message counts (`-B` negates; last wins).
    #[arg(short = 'b', overrides = "-B")]
    count_ann: bool,
    #[arg(short = 'B', overrides = "-b", hide)]
    no_count_ann: bool,
    /// Emit split user/server headers.
    #[arg(long = "split")]
    split_headers: bool,
    /// Forbid voucher attributes.
    #[arg(long = "novouchers")]
    novouchers: bool,
    /// Emit mach_msg2 (KernelServer) stubs.
    #[arg(long = "mach_msg2")]
    mach_msg2: bool,
    /// Write the user stub to FILE.
    #[arg(long = "user", value_name = "FILE")]
    user: Option<String>,
    /// Write the server stub to FILE.
    #[arg(long = "server", value_name = "FILE")]
    server: Option<String>,
    /// Write the user header to FILE.
    #[arg(long = "header", value_name = "FILE")]
    header: Option<String>,
    /// Write the server header to FILE.
    #[arg(long = "sheader", value_name = "FILE")]
    sheader: Option<String>,
    /// Write the internal header to FILE.
    #[arg(long = "iheader", value_name = "FILE")]
    iheader: Option<String>,
    /// Write the defines header to FILE.
    #[arg(long = "dheader", value_name = "FILE")]
    dheader: Option<String>,
    /// Write one user file per routine, each prefixed PREFIX.
    #[arg(short = 'i', value_name = "PREFIX")]
    prefix: Option<String>,
    /// Largest message kept on the stack.
    #[arg(long = "maxonstack", value_name = "N")]
    maxonstack: Option<i32>,
    /// Largest descriptor count in a server message.
    #[arg(long = "max_descrs", value_name = "N")]
    max_descrs: Option<i32>,
    /// Largest descriptor count in a server reply.
    #[arg(long = "max_reply_descrs", value_name = "N")]
    max_reply_descrs: Option<i32>,
    /// Print the version and exit.
    #[arg(long = "version")]
    version: bool,
    // -- `mig` driver flags (absent in pure `migcom` use) ------------------
    /// The `migcom` to run (driver mode); defaults to this binary.
    #[arg(long = "migcom", value_name = "PATH")]
    migcom: Option<String>,
    /// Target triple forwarded to the pre-processor.
    #[arg(long = "target", value_name = "TRIPLE")]
    target: Option<String>,
    /// Architecture forwarded to the pre-processor.
    #[arg(long = "arch", value_name = "ARCH")]
    arch: Option<String>,
    /// SDK root forwarded to the pre-processor.
    #[arg(long = "isysroot", value_name = "PATH")]
    isysroot: Option<String>,
    /// Sysroot forwarded to the pre-processor.
    #[arg(long = "sysroot", value_name = "PATH")]
    sysroot: Option<String>,
    /// Pre-processor program (default: $CPP or cc).
    #[arg(long = "cpp", value_name = "PROG")]
    cpp: Option<String>,
    /// Input `.defs` file (driver mode) plus verbatim pre-processor words.
    #[arg(positional)]
    inputs: Vec<String>,
}

/// Fold parsed CLI flags into compiler [`Options`]. Each toggle pair resolves
/// to its effective value: `overrides` already reset the losing spelling, so
/// the visible field holds the answer (`-q`/`-Q` → `quiet`, `-R`/`-r` →
/// `!no_msg_rpc`, …).
fn apply_args(a: &MigArgs, o: &mut Options) {
    o.quiet = a.quiet;
    o.verbose = a.verbose;
    o.use_msg_rpc = !a.no_msg_rpc;
    o.use_event_logger = a.event_logger;
    o.be_ansi_c = !a.no_ansi_c;
    o.check_ndr = a.check_ndr;
    o.gen_sym_tab = a.sym_tab;
    // NOTE: `-t` sets both flags while `-T` clears only `use_rpc_trap`, so
    // `-t -T` historically left `test_rpc_trap` set. Here both read the same
    // last-wins field; that ordering corner now clears both.
    o.test_rpc_trap = a.trap_test;
    o.use_rpc_trap = a.trap_test;
    o.short_circuit = a.short_circuit;
    o.emit_count_annotations = a.count_ann;
    o.is_voucher_code_allowed = !a.novouchers;
    o.use_mach_msg2 = a.mach_msg2;
    o.use_split_headers = a.split_headers;
    o.user_filename = a.user.clone();
    o.server_filename = a.server.clone();
    o.user_header_filename = a.header.clone();
    o.server_header_filename = a.sheader.clone();
    o.internal_header_filename = a.iheader.clone();
    o.defines_header_filename = a.dheader.clone();
    o.user_file_prefix = a.prefix.clone();
    o.max_mess_size_on_stack = a.maxonstack;
    o.max_server_descrs = a.max_descrs;
    o.max_server_reply_descrs = a.max_reply_descrs;
    o.print_version = a.version;
}

/// Rebuild the `migcom` argument vector from resolved [`Options`]: the
/// canonical spelling of every non-default setting, for the driver to exec.
fn compiler_argv(o: &Options) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    if o.quiet {
        v.push("-q".into());
    }
    if o.verbose {
        v.push("-v".into());
    }
    if !o.use_msg_rpc {
        v.push("-R".into());
    }
    if o.use_event_logger {
        v.push("-L".into());
    }
    if !o.be_ansi_c {
        v.push("-K".into());
    }
    if o.check_ndr {
        v.push("-n".into());
    }
    if o.gen_sym_tab {
        v.push("-s".into());
    }
    if o.test_rpc_trap {
        v.push("-t".into());
    }
    if o.short_circuit {
        v.push("-x".into());
    }
    if o.emit_count_annotations {
        v.push("-b".into());
    }
    if o.use_split_headers {
        v.push("-split".into());
    }
    if !o.is_voucher_code_allowed {
        v.push("-novouchers".into());
    }
    if o.use_mach_msg2 {
        v.push("-mach_msg2".into());
    }
    if let Some(p) = &o.user_filename {
        v.extend(["-user".into(), p.clone()]);
    }
    if let Some(p) = &o.server_filename {
        v.extend(["-server".into(), p.clone()]);
    }
    if let Some(p) = &o.user_header_filename {
        v.extend(["-header".into(), p.clone()]);
    }
    if let Some(p) = &o.server_header_filename {
        v.extend(["-sheader".into(), p.clone()]);
    }
    if let Some(p) = &o.internal_header_filename {
        v.extend(["-iheader".into(), p.clone()]);
    }
    if let Some(p) = &o.defines_header_filename {
        v.extend(["-dheader".into(), p.clone()]);
    }
    if let Some(p) = &o.user_file_prefix {
        v.extend(["-i".into(), p.clone()]);
    }
    if let Some(n) = o.max_mess_size_on_stack {
        v.extend(["-maxonstack".into(), n.to_string()]);
    }
    if let Some(n) = o.max_server_descrs {
        v.extend(["-max_descrs".into(), n.to_string()]);
    }
    if let Some(n) = o.max_server_reply_descrs {
        v.extend(["-max_reply_descrs".into(), n.to_string()]);
    }
    v
}

// ---------------------------------------------------------------------------
// Output helper
// ---------------------------------------------------------------------------

fn open_output(path: Option<&str>) -> io::Result<Box<dyn Write>> {
    match path {
        None => Ok(Box::new(io::sink())),
        Some(p) => {
            let f = File::create(p)
                .map_err(|e| io::Error::new(e.kind(), format!("cannot open '{p}': {e}")))?;
            Ok(Box::new(BufWriter::new(f)))
        }
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let args = MigArgs::parse();
    let prog = prog_name();

    if args.version {
        println!("{MIG_VERSION}");
        return;
    }

    // Driver mode iff a `.defs` file is given positionally. Every other
    // positional word is an unknown flag (e.g. `-D`, `-I`) or its value and
    // is forwarded to the pre-processor verbatim, in order.
    let mut defs: Option<&String> = None;
    let mut cpp_extra: Vec<String> = Vec::new();
    for w in &args.inputs {
        if w.ends_with(".defs") {
            if defs.is_some() {
                eprintln!("{prog}: only one input file allowed: '{w}'");
                process::exit(1);
            }
            defs = Some(w);
        } else {
            cpp_extra.push(w.clone());
        }
    }

    if let Some(defs) = defs {
        let mut opts = Options::default();
        apply_args(&args, &mut opts);
        run_driver(&prog, &args, defs, &cpp_extra, &opts);
        return;
    }

    // Compiler mode: no input file, so pre-processed `.defs` comes from
    // stdin. Historically any stray word was `unknown flag`; keep that error.
    if let Some(first) = args.inputs.first() {
        eprintln!("{prog}: unknown flag: '{first}'");
        process::exit(1);
    }

    let mut opts = Options::default();
    apply_args(&args, &mut opts);

    // Read pre-processed source from stdin
    let mut src = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut src) {
        eprintln!("migcom: reading stdin: {e}");
        process::exit(1);
    }

    // Lex
    let tokens = lexer::tokenise(&src);

    // Parse
    let mut diag = Diag::new("<stdin>", &src, opts.quiet);
    let mut p = parser::Parser::new(&tokens, &mut diag);
    let stmts = p.parse_statements();
    let mut types = std::mem::take(&mut p.types);
    drop(p);

    if !opts.quiet {
        for w in types.warnings.drain(..) {
            eprintln!("warning: {w}");
        }
    }
    for e in types.errors.drain(..) {
        diag.error_noloc(&e);
    }
    if diag.error_count > 0 {
        eprintln!("migcom: {} error(s) found — aborting", diag.error_count);
        process::exit(1);
    }

    // Semantic lowering — fill in Options and check routines in order
    let module = lower::lower(&stmts, &mut opts, &mut types, &mut diag);

    if diag.error_count > 0 {
        eprintln!("migcom: {} error(s) found — aborting", diag.error_count);
        process::exit(1);
    }

    // Finalize derived file names and validate option combinations
    if let Err(e) = opts.finalize() {
        eprintln!("migcom: {e}");
        process::exit(1);
    }
    let gen = codegen::Gen {
        stmts: &stmts,
        routines: &module.routines,
        rt_number: module.rt_number,
        types: &types,
        opts: &opts,
    };

    if opts.verbose {
        eprintln!(
            "Subsystem {}: base = {}{}{}",
            opts.subsystem_name.as_deref().unwrap_or("?"),
            opts.subsystem_base,
            if opts.is_kernel_user {
                ", KernelUser"
            } else {
                ""
            },
            if opts.is_kernel_server {
                ", KernelServer"
            } else {
                ""
            },
        );
    }

    // -----------------------------------------------------------------------
    // Code generation
    // -----------------------------------------------------------------------

    // User header
    let uheader_path = opts.user_header_filename.as_deref();
    if opts.verbose {
        eprintln!("Writing {} …", uheader_path.unwrap_or("/dev/null"));
    }
    let mut uheader = open_output(uheader_path).unwrap_or_else(|e| {
        eprintln!("migcom: {e}");
        process::exit(1);
    });
    codegen::header::write_user_header(&mut *uheader, &gen).unwrap_or_else(|e| {
        eprintln!("migcom: writing user header: {e}");
        process::exit(1);
    });

    // Server header (optional)
    if let Some(path) = opts.server_header_filename.as_deref() {
        if opts.verbose {
            eprintln!("Writing {path} …");
        }
        let mut sh = open_output(Some(path)).unwrap_or_else(|e| {
            eprintln!("migcom: {e}");
            process::exit(1);
        });
        codegen::header::write_server_header(&mut *sh, &gen).unwrap_or_else(|e| {
            eprintln!("migcom: writing server header: {e}");
            process::exit(1);
        });
    }

    // Defines header (optional)
    if let Some(path) = opts.defines_header_filename.as_deref() {
        if opts.verbose {
            eprintln!("Writing {path} …");
        }
        let mut dh = open_output(Some(path)).unwrap_or_else(|e| {
            eprintln!("migcom: {e}");
            process::exit(1);
        });
        codegen::header::write_defines_header(&mut *dh, &gen).unwrap_or_else(|e| {
            eprintln!("migcom: writing defines header: {e}");
            process::exit(1);
        });
    }

    // User stub
    if let Some(prefix) = opts.user_file_prefix.as_deref() {
        // -i mode: one file per routine
        if opts.verbose {
            eprintln!("Writing individual user files …");
        }
        for rt in &module.routines {
            let path = format!("{prefix}{}.c", rt.name);
            if opts.verbose {
                eprintln!("  {path}");
            }
            let mut f = open_output(Some(&path)).unwrap_or_else(|e| {
                eprintln!("migcom: {e}");
                process::exit(1);
            });
            codegen::user::write_user_individual(&mut *f, &gen, rt).unwrap_or_else(|e| {
                eprintln!("migcom: {e}");
                process::exit(1);
            });
        }
    } else {
        let user_path = opts.user_filename.as_deref();
        if opts.verbose {
            eprintln!("Writing {} …", user_path.unwrap_or("/dev/null"));
        }
        let mut user = open_output(user_path).unwrap_or_else(|e| {
            eprintln!("migcom: {e}");
            process::exit(1);
        });
        codegen::user::write_user(&mut *user, &gen).unwrap_or_else(|e| {
            eprintln!("migcom: writing user stub: {e}");
            process::exit(1);
        });
    }

    // Server stub
    let server_path = opts.server_filename.as_deref();
    if opts.verbose {
        eprintln!("Writing {} …", server_path.unwrap_or("/dev/null"));
    }
    let mut server = open_output(server_path).unwrap_or_else(|e| {
        eprintln!("migcom: {e}");
        process::exit(1);
    });
    codegen::server::write_server(&mut *server, &gen).unwrap_or_else(|e| {
        eprintln!("migcom: writing server stub: {e}");
        process::exit(1);
    });

    if opts.verbose {
        eprintln!("done.");
    }
}

// ---------------------------------------------------------------------------
// `mig` driver: pre-process the `.defs` file, pipe it into `migcom`
// ---------------------------------------------------------------------------

/// `argv[0]`'s file name, for diagnostics (`mig` vs `migcom`).
fn prog_name() -> String {
    std::env::args_os()
        .next()
        .and_then(|a| {
            std::path::Path::new(&a)
                .file_name()
                .and_then(|s| s.to_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "mig".to_string())
}

fn run_driver(prog: &str, args: &MigArgs, defs: &str, cpp_extra: &[String], opts: &Options) {
    let cpp_prog = args
        .cpp
        .clone()
        .or_else(|| std::env::var("CPP").ok().filter(|s| !s.trim().is_empty()))
        .unwrap_or_else(|| "cc".to_string());
    // `-migcom` names the compiler; without it this binary compiles too.
    let migcom_prog = match &args.migcom {
        Some(p) => p.clone(),
        None => std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "migcom".to_string()),
    };

    let mut cpp_cmd = process::Command::new(&cpp_prog);
    cpp_cmd.arg("-E").arg("-x").arg("c");
    if let Some(a) = &args.arch {
        cpp_cmd.arg("-arch").arg(a);
    }
    if let Some(t) = &args.target {
        cpp_cmd.arg("-target").arg(t);
    }
    if let Some(s) = &args.isysroot {
        cpp_cmd.arg("-isysroot").arg(s);
    }
    if let Some(s) = &args.sysroot {
        cpp_cmd.arg(format!("--sysroot={s}"));
    }
    cpp_cmd.args(cpp_extra);
    cpp_cmd.arg(defs);
    cpp_cmd.stderr(process::Stdio::inherit());
    cpp_cmd.stdout(process::Stdio::piped());

    let migcom_argv = compiler_argv(opts);
    if opts.verbose {
        eprintln!(
            "{prog}: {cpp_cmd:?} | {migcom_prog} {}",
            migcom_argv.join(" ")
        );
    }

    let mut cpp_child = match cpp_cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{prog}: cannot run preprocessor '{cpp_prog}': {e}");
            process::exit(1);
        }
    };
    let cpp_out = cpp_child.stdout.take().unwrap_or_else(|| {
        eprintln!("{prog}: cannot pipe preprocessor output");
        process::exit(1);
    });
    let mut migcom_child = match process::Command::new(&migcom_prog)
        .args(&migcom_argv)
        .stdin(process::Stdio::from(cpp_out))
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{prog}: cannot run '{migcom_prog}': {e}");
            process::exit(1);
        }
    };

    let migcom_status = migcom_child.wait().unwrap_or_else(|e| {
        eprintln!("{prog}: waiting for '{migcom_prog}': {e}");
        process::exit(1);
    });
    let cpp_status = cpp_child.wait().unwrap_or_else(|e| {
        eprintln!("{prog}: waiting for '{cpp_prog}': {e}");
        process::exit(1);
    });
    if !cpp_status.success() {
        eprintln!("{prog}: preprocessor exited with {cpp_status}");
        process::exit(1);
    }
    if !migcom_status.success() {
        process::exit(migcom_status.code().unwrap_or(1));
    }
    if opts.verbose {
        eprintln!("done.");
    }
}

#[cfg(test)]
mod cli_tests {
    use super::{apply_args, compiler_argv, MigArgs, Options};
    use winnow_args::Args;

    fn parse(line: &[&str]) -> MigArgs {
        MigArgs::parse_from(line).unwrap_or_else(|e| panic!("{line:?}: {e}"))
    }

    fn opts(line: &[&str]) -> Options {
        let a = parse(line);
        let mut o = Options::default();
        apply_args(&a, &mut o);
        o
    }

    #[test]
    fn defaults_match_legacy() {
        let o = opts(&[]);
        assert!(!o.quiet && !o.verbose);
        assert!(o.use_msg_rpc && !o.gen_sym_tab && !o.use_event_logger);
        assert!(o.be_ansi_c && !o.check_ndr && !o.short_circuit);
        assert!(!o.use_rpc_trap && !o.test_rpc_trap);
        assert!(o.is_voucher_code_allowed && !o.emit_count_annotations);
        assert!(!o.use_mach_msg2 && !o.use_split_headers);
        assert!(o.user_filename.is_none());
    }
    #[test]
    fn toggle_pairs_last_wins() {
        assert!(opts(&["-q"]).quiet);
        assert!(!opts(&["-q", "-Q"]).quiet);
        assert!(opts(&["-Q", "-q"]).quiet);
        assert!(opts(&["-v", "-V", "-v"]).verbose);
        assert!(!opts(&["-r", "-R"]).use_msg_rpc);
        assert!(opts(&["-R", "-r"]).use_msg_rpc);
        assert!(opts(&["-L"]).use_event_logger);
        assert!(!opts(&["-L", "-l"]).use_event_logger);
        assert!(!opts(&["-k", "-K"]).be_ansi_c);
        assert!(opts(&["-K", "-k"]).be_ansi_c);
        assert!(opts(&["-n", "-N", "-n"]).check_ndr);
        assert!(opts(&["-s"]).gen_sym_tab && !opts(&["-s", "-S"]).gen_sym_tab);
        assert!(opts(&["-t"]).test_rpc_trap && opts(&["-t"]).use_rpc_trap);
        assert!(!opts(&["-t", "-T"]).use_rpc_trap);
        assert!(opts(&["-x"]).short_circuit && !opts(&["-x", "-X"]).short_circuit);
        assert!(opts(&["-b"]).emit_count_annotations);
        assert!(!opts(&["-novouchers"]).is_voucher_code_allowed);
        assert!(opts(&["-split"]).use_split_headers);
        assert!(opts(&["-mach_msg2"]).use_mach_msg2);
    }

    #[test]
    fn value_flags() {
        let o = opts(&[
            "-user",
            "a.c",
            "-server",
            "b.c",
            "-header",
            "c.h",
            "-sheader",
            "d.h",
            "-iheader",
            "e.h",
            "-dheader",
            "f.h",
            "-i",
            "pre_",
            "-maxonstack",
            "1024",
            "-max_descrs",
            "8",
            "-max_reply_descrs",
            "4",
        ]);
        assert_eq!(o.user_filename.as_deref(), Some("a.c"));
        assert_eq!(o.server_filename.as_deref(), Some("b.c"));
        assert_eq!(o.user_header_filename.as_deref(), Some("c.h"));
        assert_eq!(o.server_header_filename.as_deref(), Some("d.h"));
        assert_eq!(o.internal_header_filename.as_deref(), Some("e.h"));
        assert_eq!(o.defines_header_filename.as_deref(), Some("f.h"));
        assert_eq!(o.user_file_prefix.as_deref(), Some("pre_"));
        assert_eq!(o.max_mess_size_on_stack, Some(1024));
        assert_eq!(o.max_server_descrs, Some(8));
        assert_eq!(o.max_server_reply_descrs, Some(4));
        // -iheader wins over -i with an attached value (long_only).
        let o = opts(&["-iheader", "g.h"]);
        assert_eq!(o.internal_header_filename.as_deref(), Some("g.h"));
        assert!(o.user_file_prefix.is_none());
    }

    #[test]
    fn single_dash_longs_and_driver_flags() {
        let a = parse(&[
            "-novouchers",
            "-migcom",
            "mig",
            "-DAPPLE",
            "-DKERNEL",
            "-I/osfmk",
            "-target",
            "arm64-apple-macho",
            "in.defs",
        ]);
        assert_eq!(a.migcom.as_deref(), Some("mig"));
        assert_eq!(a.target.as_deref(), Some("arm64-apple-macho"));
        assert_eq!(
            a.inputs,
            ["-DAPPLE", "-DKERNEL", "-I/osfmk", "in.defs"]
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        );
        // The `-s…` longs are not the `-s` switch.
        let o = opts(&["-server", "x.c", "-sheader", "y.h", "-split"]);
        assert_eq!(o.server_filename.as_deref(), Some("x.c"));
        assert_eq!(o.server_header_filename.as_deref(), Some("y.h"));
        assert!(!o.gen_sym_tab);
    }

    #[test]
    fn compiler_argv_round_trip() {
        let o = opts(&["-v", "-R", "-K", "-s", "-user", "u.c", "-maxonstack", "512"]);
        let v = compiler_argv(&o);
        assert!(v.contains(&"-v".to_string()));
        assert!(v.contains(&"-R".to_string()));
        assert!(v.contains(&"-K".to_string()));
        assert!(v.contains(&"-s".to_string()));
        // Re-parsing the rebuilt argv resolves identically.
        let refs: Vec<&str> = v.iter().map(String::as_str).collect();
        let o2 = opts(&refs);
        assert!(o2.verbose && !o2.use_msg_rpc && !o2.be_ansi_c && o2.gen_sym_tab);
        assert_eq!(o2.user_filename.as_deref(), Some("u.c"));
        assert_eq!(o2.max_mess_size_on_stack, Some(512));
    }
}
