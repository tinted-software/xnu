//! Host replacement for the part of Apple's `dtrace` that libmalloc uses:
//!
//!     dtrace -h -s <provider.d> -o <header.h>
//!
//! The output mirrors `dtrace_program_header` and its helpers in upstream
//! lib/libdtrace/common/dt_program.c, and the name/attribute encodings in
//! lib/libdtrace/apple/dt_ld.cpp. The probe-name encodings are what the link
//! step (`dtrace -G`, not implemented here) reads back, so they must match.
//!
//! Unsupported input is an error, not a guess: argument types must be C base
//! types (which dtrace does not typedef-encode), and every provider must carry
//! all five `#pragma D attributes` lines.

use std::fs;
use std::path::Path;
use std::process::exit;

const SEP: &str = "$";

/// Stability levels and classes, from bsd/sys/dtrace.h.
fn stability_value(name: &str) -> Option<u8> {
    Some(match name {
        "Internal" => 0,
        "Private" => 1,
        "Obsolete" => 2,
        "External" => 3,
        "Unstable" => 4,
        "Evolving" => 5,
        "Stable" => 6,
        "Standard" => 7,
        _ => return None,
    })
}

fn class_value(name: &str) -> Option<u8> {
    Some(match name {
        "Unknown" => 0,
        "CPU" => 1,
        "Platform" => 2,
        "Group" => 3,
        "ISA" => 4,
        "Common" => 5,
        _ => return None,
    })
}

/// Argument types the encoder knows how to name. dtrace typedefs these (or
/// they are C base types), so the typedef table never needs an entry.
const BASE_TYPES: &[&str] = &[
    "void", "char", "short", "int", "long", "long long", "float", "double",
    "unsigned char", "unsigned short", "unsigned", "unsigned int", "unsigned long",
    "unsigned long long", "signed char", "_Bool",
    "int8_t", "int16_t", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t",
    "uint64_t", "intptr_t", "uintptr_t", "size_t", "ssize_t", "ptrdiff_t",
];

#[derive(Clone)]
struct Arg {
    /// ctf_type_lname() form: base type plus one space and the stars, e.g. "void *".
    lname: String,
    /// Number of '*' in the declared type.
    stars: usize,
}

#[derive(Clone)]
struct Probe {
    name: String,
    args: Vec<Arg>,
}

struct Provider {
    name: String,
    /// Stability triples in encoding order: provider, module, function, name, args.
    attrs: [[u8; 3]; 5],
    probes: Vec<Probe>,
}

fn die(msg: &str) -> ! {
    eprintln!("dtrace: {msg}");
    exit(1);
}

/// dt_header_fmt_macro: lowercase to upper, '-' and '.' to '_'.
fn fmt_macro(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => c.to_ascii_uppercase(),
            '-' | '.' => '_',
            _ => c,
        })
        .collect()
}

/// dt_header_fmt_func: '-' becomes "__".
fn fmt_func(s: &str) -> String {
    s.replace('-', "__")
}

fn hex(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

fn parse_arg(text: &str, lineno: usize) -> Arg {
    let text = text.trim();
    let stars = text.matches('*').count();
    let base = text.replace('*', "");
    let base = base.split_whitespace().collect::<Vec<_>>().join(" ");
    if !BASE_TYPES.contains(&base.as_str()) {
        die(&format!(
            "line {lineno}: argument type '{base}' needs CTF typedef encoding, which this tool does not implement"
        ));
    }
    let lname = if stars == 0 {
        base
    } else {
        format!("{base} {}", "*".repeat(stars))
    };
    Arg { lname, stars }
}

fn parse(src: &str) -> Vec<Provider> {
    let mut providers: Vec<Provider> = Vec::new();
    let mut pending_attrs: Vec<(String, String, [u8; 3])> = Vec::new();

    for (idx, raw) in src.lines().enumerate() {
        let lineno = idx + 1;
        let line = raw.trim();

        if let Some(rest) = line.strip_prefix("#pragma D attributes ") {
            // <stab>/<data>/<class> provider <name> <kind>
            let toks: Vec<&str> = rest.split_whitespace().collect();
            if toks.len() != 4 || toks[1] != "provider" {
                die(&format!("line {lineno}: unsupported pragma"));
            }
            let parts: Vec<&str> = toks[0].split('/').collect();
            if parts.len() != 3 {
                die(&format!("line {lineno}: malformed attribute triple"));
            }
            let triple = [
                stability_value(parts[0]).unwrap_or_else(|| die(&format!("line {lineno}: stability {}", parts[0]))),
                stability_value(parts[1]).unwrap_or_else(|| die(&format!("line {lineno}: stability {}", parts[1]))),
                class_value(parts[2]).unwrap_or_else(|| die(&format!("line {lineno}: class {}", parts[2]))),
            ];
            pending_attrs.push((toks[2].to_string(), toks[3].to_string(), triple));
            continue;
        }

        if let Some(rest) = line.strip_prefix("provider ") {
            let name = rest.split(|c: char| c == '{' || c.is_whitespace()).next().unwrap_or("");
            if name.is_empty() {
                die(&format!("line {lineno}: provider without a name"));
            }
            providers.push(Provider {
                name: name.to_string(),
                attrs: [[0; 3]; 5],
                probes: Vec::new(),
            });
            continue;
        }

        if let Some(rest) = line.strip_prefix("probe ") {
            let Some(p) = providers.last_mut() else {
                die(&format!("line {lineno}: probe outside a provider"));
            };
            let open = rest.find('(').unwrap_or_else(|| die(&format!("line {lineno}: no '('")));
            let close = rest.rfind(')').unwrap_or_else(|| die(&format!("line {lineno}: no ')'")));
            let name = rest[..open].trim().to_string();
            let inner = rest[open + 1..close].trim();
            let args = if inner.is_empty() || inner == "void" {
                Vec::new()
            } else {
                inner.split(',').map(|a| parse_arg(a, lineno)).collect()
            };
            p.probes.push(Probe { name, args });
            continue;
        }
    }

    // Attach attributes to providers by kind, in dt_ld_encode_stability order.
    const KINDS: [&str; 5] = ["provider", "module", "function", "name", "args"];
    for p in &mut providers {
        for (slot, kind) in KINDS.iter().enumerate() {
            let found = pending_attrs
                .iter()
                .rev()
                .find(|(prov, k, _)| prov == &p.name && k == kind);
            match found {
                Some((_, _, t)) => p.attrs[slot] = *t,
                None => die(&format!("provider {}: missing '#pragma D attributes ... {kind}'", p.name)),
            }
        }
    }
    providers
}

/// dt_ld_encode_stability: ___dtrace_stability$<prov>$v1$<15 hex-ish values>.
/// The format is %x per value, so each attribute prints as a plain digit.
fn encode_stability(p: &Provider) -> String {
    let values: Vec<String> = p
        .attrs
        .iter()
        .flat_map(|t| t.iter().map(|v| format!("{v:x}")))
        .collect();
    format!(
        "___dtrace_stability{SEP}{}{SEP}v1{SEP}{}",
        p.name,
        values.join("_")
    )
}

/// dt_ld_encode_typedefs: no typedef entries, because every argument type is
/// a base type (see BASE_TYPES).
fn encode_typedefs(p: &Provider) -> String {
    format!("___dtrace_typedefs{SEP}{}{SEP}v2", p.name)
}

fn encode_probe(prov: &str, probe: &str, args: &[Arg]) -> String {
    let mut s = format!("__dtrace_probe{SEP}{prov}{SEP}{probe}{SEP}v1");
    for a in args {
        s.push('$');
        s.push_str(&hex(&a.lname));
    }
    s
}

fn encode_isenabled(prov: &str, probe: &str) -> String {
    format!("__dtrace_isenabled{SEP}{prov}{SEP}{probe}{SEP}v1")
}

/// dt_header_probe: the macro for one probe, in enabled or empty form.
fn probe_macro(out: &mut String, pmname: &str, pfname: &str, p: &Probe, empty: bool) {
    let mname = fmt_macro(&p.name);
    let fname = fmt_func(&p.name);
    let params: Vec<String> = (0..p.args.len()).map(|i| format!("arg{i}")).collect();

    out.push_str(&format!("#define\t{pmname}_{mname}({}) \\\n", params.join(", ")));
    out.push_str("do { \\\n\t");
    if !empty {
        out.push_str(&format!("__asm__ volatile(\".reference \" {pmname}_TYPEDEFS); \\\n\t"));
        out.push_str(&format!("{}({}); \\\n\t", encode_probe(pfname, &fname, &p.args), params.join(", ")));
        out.push_str(&format!("__asm__ volatile(\".reference \" {pmname}_STABILITY); \\\n"));
    }
    out.push_str("} while (0)\n");

    if !empty {
        out.push_str(&format!("#define\t{pmname}_{mname}_ENABLED() \\\n"));
        out.push_str(&format!("\t({{ int _r = {}(); \\\n", encode_isenabled(pfname, &fname)));
        out.push_str("\t\t__asm__ volatile(\"\"); \\\n");
        out.push_str("\t\t_r; })\n");
    } else {
        out.push_str(&format!("#define\t{pmname}_{mname}_ENABLED() (0)\n"));
    }
}

/// dt_header_decl: the extern declarations for the link-time probe functions.
fn probe_decl(out: &mut String, pfname: &str, p: &Probe) {
    let fname = fmt_func(&p.name);
    out.push_str(&format!("extern void {}(", encode_probe(pfname, &fname, &p.args)));
    if p.args.is_empty() {
        out.push_str("void");
    }
    let tys: Vec<String> = p
        .args
        .iter()
        .map(|a| {
            // dt_is_single_rank_pointer_type: a pointer to a non-pointer, non-function.
            if a.stars == 1 {
                format!("const {}", a.lname)
            } else {
                a.lname.clone()
            }
        })
        .collect();
    out.push_str(&tys.join(", "));
    out.push_str(");\n");
    out.push_str(&format!("extern int {}(void);\n", encode_isenabled(pfname, &fname)));
}

/// dt_header_provider.
fn provider_block(out: &mut String, p: &Provider) {
    let pmname = fmt_macro(&p.name);
    let pfname = fmt_func(&p.name);

    out.push_str(&format!("#define {pmname}_STABILITY \"{}\"\n\n", encode_stability(p)));
    out.push_str(&format!("#define {pmname}_TYPEDEFS \"{}\"\n\n", encode_typedefs(p)));
    out.push_str("#if !defined(DTRACE_PROBES_DISABLED) || !DTRACE_PROBES_DISABLED\n\n");
    for pr in &p.probes {
        probe_macro(out, &pmname, &pfname, pr, false);
    }
    out.push_str("\n\n");
    for pr in &p.probes {
        probe_decl(out, &pfname, pr);
    }
    out.push_str("\n#else\n\n");
    for pr in &p.probes {
        probe_macro(out, &pmname, &pfname, pr, true);
    }
    out.push_str("\n#endif /* !defined(DTRACE_PROBES_DISABLED) || !DTRACE_PROBES_DISABLED */\n\n");
}

/// dtrace_program_header, with the -o path as the guard name.
fn program_header(providers: &[Provider], fname: &str) -> String {
    let base = Path::new(fname)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(fname);
    let guard = fmt_macro(base);

    let mut out = String::new();
    out.push_str("/*\n * Generated by dtrace(1M).\n */\n\n");
    out.push_str(&format!("#ifndef\t_{guard}\n#define\t_{guard}\n\n"));
    out.push_str("#if !defined(DTRACE_PROBES_DISABLED) || !DTRACE_PROBES_DISABLED\n");
    out.push_str("#include <unistd.h>\n");
    out.push_str("\n#endif /* !defined(DTRACE_PROBES_DISABLED) || !DTRACE_PROBES_DISABLED */\n\n");
    out.push_str("#ifdef\t__cplusplus\nextern \"C\" {\n#endif\n\n");
    for p in providers {
        provider_block(&mut out, p);
    }
    out.push_str("\n#ifdef\t__cplusplus\n}\n#endif\n");
    out.push_str(&format!("\n#endif\t/* _{guard} */\n"));
    out
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut script: Option<String> = None;
    let mut output: Option<String> = None;
    let mut header_mode = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" => header_mode = true,
            "-s" => {
                i += 1;
                script = Some(args.get(i).cloned().unwrap_or_else(|| die("-s needs a path")));
            }
            "-o" => {
                i += 1;
                output = Some(args.get(i).cloned().unwrap_or_else(|| die("-o needs a path")));
            }
            "-G" => die("-G is not needed: the linker (mold) generates the DOF at link time"),
            other => die(&format!("unsupported option {other}")),
        }
        i += 1;
    }

    if !header_mode {
        die("only -h (header generation) is implemented; the linker handles -G");
    }
    let script = script.unwrap_or_else(|| die("-s <provider.d> is required"));
    let output = output.unwrap_or_else(|| die("-o <header> is required"));

    let src = fs::read_to_string(&script).unwrap_or_else(|e| die(&format!("reading {script}: {e}")));
    let providers = parse(&src);
    if providers.is_empty() {
        die(&format!("{script}: no provider defined"));
    }
    let header = program_header(&providers, &output);
    fs::write(&output, header).unwrap_or_else(|e| die(&format!("writing {output}: {e}")));
}
