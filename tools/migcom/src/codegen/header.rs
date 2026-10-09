// SPDX-License-Identifier: MIT
// Header generation — a port of migcom.tproj/header.c.

use std::io::{self, Write};

use super::utils::{
    return_type_str, write_bogus_server_routine_annotation_define, write_import, write_includes,
    write_list, write_mig_external, write_reply_types, write_request_types, write_server_var_decl,
    write_user_var_decl,
};
use super::Gen;
use crate::ast::{ImportKind, Statement};
use crate::routine::{ak, count_arg_descriptors, Routine};

/// `WriteProlog`
fn write_prolog(
    w: &mut dyn Write,
    g: &Gen,
    protect: Option<&str>,
    more: bool,
    isuser: bool,
) -> io::Result<()> {
    if let Some(p) = protect {
        writeln!(w, "#ifndef\t_{p}")?;
        writeln!(w, "#define\t_{p}")?;
        writeln!(w)?;
    }
    writeln!(w, "/* Module {} */", g.subsystem())?;
    writeln!(w)?;
    if more {
        write_includes(w, g, isuser, g.opts.use_split_headers)?;
    }
    let ann = if g.opts.emit_count_annotations {
        "__unsafe_indexable"
    } else {
        ""
    };
    writeln!(w, "#ifdef AUTOTEST")?;
    writeln!(w, "#ifndef FUNCTION_PTR_T")?;
    writeln!(w, "#define FUNCTION_PTR_T")?;
    writeln!(
        w,
        "typedef void (*function_ptr_t)(mach_port_t, char *{ann}, mach_msg_type_number_t);"
    )?;
    writeln!(w, "typedef struct {{")?;
    writeln!(w, "        char            *{ann} name;")?;
    writeln!(w, "        function_ptr_t  function;")?;
    writeln!(w, "}} function_table_entry;")?;
    writeln!(w, "typedef function_table_entry   *function_table_t;")?;
    writeln!(w, "#endif /* FUNCTION_PTR_T */")?;
    writeln!(w, "#endif /* AUTOTEST */")?;
    let sub = g.subsystem();
    writeln!(w, "\n#ifndef\t{sub}_MSG_COUNT")?;
    writeln!(w, "#define\t{sub}_MSG_COUNT\t{}", g.rt_number)?;
    writeln!(w, "#endif\t/* {sub}_MSG_COUNT */\n")
}

/// `WriteETAPDefines`
fn write_etap_defines(w: &mut dyn Write, g: &Gen) -> io::Result<()> {
    let sub = g.subsystem();
    writeln!(w, "\n#ifndef subsystem_to_name_map_{sub}")?;
    writeln!(w, "#define subsystem_to_name_map_{sub} \\")?;
    let entries: Vec<String> = g
        .routines
        .iter()
        .map(|rt| {
            format!(
                "    {{ \"{}\", {} }}",
                rt.name,
                g.opts.subsystem_base + rt.number
            )
        })
        .collect();
    write!(w, "{}", entries.join(",\\\n"))?;
    writeln!(w, "\n#endif")
}

/// `WriteEpilog`
fn write_epilog(w: &mut dyn Write, g: &Gen, protect: Option<&str>, isuser: bool) -> io::Result<()> {
    let defname = if isuser {
        "__AfterMigUserHeader"
    } else {
        "__AfterMigServerHeader"
    };
    write_etap_defines(w, g)?;
    writeln!(w, "\n#ifdef {defname}\n{defname}\n#endif /* {defname} */")?;
    if let Some(p) = protect {
        writeln!(w)?;
        writeln!(w, "#endif\t /* _{p} */")?;
    }
    Ok(())
}

/// `WriteUserRoutine`: the user stub prototype.
fn write_user_routine(w: &mut dyn Write, g: &Gen, rt: &Routine) -> io::Result<()> {
    writeln!(w)?;
    writeln!(w, "/* {} {} */", rt.kind_str(), rt.name)?;
    write_mig_external(w)?;
    writeln!(w, "{} {}", return_type_str(g, rt), rt.user_name)?;
    writeln!(w, "(")?;
    write_list(w, rt, ak::USER_ARG, ",\n", "\n", |w, a| {
        write_user_var_decl(w, g, rt, a)
    })?;
    writeln!(w, ");")
}

/// `WriteUserRequestUnion`
fn write_user_request_union(w: &mut dyn Write, g: &Gen) -> io::Result<()> {
    let n = format!("{}{}_subsystem", g.opts.user_prefix, g.subsystem());
    writeln!(w, "/* union of all requests */")?;
    writeln!(w)?;
    writeln!(w, "#ifndef __RequestUnion__{n}__defined")?;
    writeln!(w, "#define __RequestUnion__{n}__defined")?;
    writeln!(w, "union __RequestUnion__{n} {{")?;
    for rt in g.routines {
        writeln!(w, "\t__Request__{}_t Request_{};", rt.name, rt.user_name)?;
    }
    writeln!(w, "}};")?;
    writeln!(w, "#endif /* !__RequestUnion__{n}__defined */")
}

/// `WriteUserReplyUnion`
fn write_user_reply_union(w: &mut dyn Write, g: &Gen) -> io::Result<()> {
    let n = format!("{}{}_subsystem", g.opts.user_prefix, g.subsystem());
    writeln!(w, "/* union of all replies */")?;
    writeln!(w)?;
    writeln!(w, "#ifndef __ReplyUnion__{n}__defined")?;
    writeln!(w, "#define __ReplyUnion__{n}__defined")?;
    writeln!(w, "union __ReplyUnion__{n} {{")?;
    for rt in g.routines {
        writeln!(w, "\t__Reply__{}_t Reply_{};", rt.name, rt.user_name)?;
    }
    writeln!(w, "}};")?;
    writeln!(w, "#endif /* !__RequestUnion__{n}__defined */")
}

/// `WriteUserHeader`
pub fn write_user_header(w: &mut dyn Write, g: &Gen) -> io::Result<()> {
    let protect = format!("{}_user_", g.subsystem());
    write_prolog(w, g, Some(&protect), true, true)?;
    for stmt in g.stmts {
        if let Statement::Import { kind, filename } = stmt {
            if matches!(
                kind,
                ImportKind::Import | ImportKind::UImport | ImportKind::DImport
            ) {
                write_import(w, filename)?;
            }
        }
    }
    writeln!(w)?;
    writeln!(w, "#ifdef __BeforeMigUserHeader")?;
    writeln!(w, "__BeforeMigUserHeader")?;
    writeln!(w, "#endif /* __BeforeMigUserHeader */")?;
    writeln!(w)?;
    writeln!(w, "#include <sys/cdefs.h>")?;
    writeln!(w, "__BEGIN_DECLS")?;
    writeln!(w)?;
    for rt in g.routines {
        write_user_routine(w, g, rt)?;
    }
    writeln!(w)?;
    writeln!(w, "__END_DECLS")?;
    writeln!(w)?;
    writeln!(
        w,
        "/********************** Caution **************************/"
    )?;
    writeln!(
        w,
        "/* The following data types should be used to calculate  */"
    )?;
    writeln!(
        w,
        "/* maximum message sizes only. The actual message may be */"
    )?;
    writeln!(
        w,
        "/* shorter than these types because of variable arrays or */"
    )?;
    writeln!(
        w,
        "/* the presence of holes.                                */"
    )?;
    writeln!(
        w,
        "/********************** Caution **************************/"
    )?;
    writeln!(w)?;
    write_request_types(w, g)?;
    write_user_request_union(w, g)?;
    write_reply_types(w, g)?;
    write_user_reply_union(w, g)?;
    write_epilog(w, g, Some(&protect), true)
}

/// `WriteServerRoutine`: the server work function prototype.
pub fn write_server_routine(w: &mut dyn Write, g: &Gen, rt: &Routine) -> io::Result<()> {
    writeln!(w)?;
    writeln!(w, "/* {} {} */", rt.kind_str(), rt.name)?;
    write_mig_external(w)?;
    // MIG_SERVER_ROUTINE marks MIG server routines for static analysis.
    writeln!(
        w,
        "MIG_SERVER_ROUTINE\n{} {}",
        return_type_str(g, rt),
        rt.server_name
    )?;
    writeln!(w, "(")?;
    write_list(w, rt, ak::SERVER_ARG, ",\n", "\n", |w, a| {
        write_server_var_decl(w, g, rt, a)
    })?;
    writeln!(w, ");")
}

/// `WriteDispatcher` (header): the demux prototypes and the subsystem
/// descriptor type.
fn write_dispatcher(w: &mut dyn Write, g: &Gen) -> io::Result<()> {
    let (kern_, k, kernel) = if g.opts.use_mach_msg2 {
        ("kern_", "k", "kernel ")
    } else {
        ("", "", "")
    };
    let demux = g.server_demux();
    let subsys = g.server_subsys();
    let _descr_count: u32 = g
        .routines
        .iter()
        .map(|rt| count_arg_descriptors(rt, g.types).0)
        .sum();
    writeln!(w)?;
    write_mig_external(w)?;
    write!(w, "boolean_t {demux}(")?;
    write!(w, "\n\t\tmach_msg_header_t *InHeadP,")?;
    if !g.opts.use_mach_msg2 {
        write!(w, "\n\t\tmach_msg_header_t *OutHeadP")?;
    } else {
        write!(w, "\n\t\tvoid *InDataP,")?;
        write!(w, "\n\t\tmach_msg_max_trailer_t *InTrailerP,")?;
        write!(w, "\n\t\tmach_msg_header_t *OutHeadP,")?;
        write!(w, "\n\t\tvoid *OutDataP")?;
    }
    writeln!(w, ");\n")?;
    write_mig_external(w)?;
    writeln!(w, "mig_{kern_}routine_t {demux}_routine(")?;
    writeln!(w, "\t\tmach_msg_header_t *InHeadP);\n")?;
    writeln!(
        w,
        "\n/* Description of this {kernel}subsystem, for use in direct RPC */"
    )?;
    writeln!(w, "extern const struct {subsys} {{")?;
    writeln!(
        w,
        "\tmig_{kern_}server_routine_t\t{k}server;\t/* Server routine */"
    )?;
    writeln!(w, "\tmach_msg_id_t\tstart;\t/* Min routine number */")?;
    writeln!(w, "\tmach_msg_id_t\tend;\t/* Max routine number + 1 */")?;
    writeln!(w, "\tunsigned int\tmaxsize;\t/* Max msg size */")?;
    writeln!(w, "\tvm_address_t\treserved;\t/* Reserved */")?;
    writeln!(
        w,
        "\tstruct {kern_}routine_descriptor\t/* Array of routine descriptors */"
    )?;
    writeln!(w, "\t\t{k}routine[{}];", g.rt_number)?;
    writeln!(w, "}} {subsys};")?;
    writeln!(w)
}

/// `WriteServerRequestUnion`
pub fn write_server_request_union(w: &mut dyn Write, g: &Gen) -> io::Result<()> {
    let s = g.server_subsys();
    writeln!(w)?;
    writeln!(w, "/* union of all requests */")?;
    writeln!(w)?;
    writeln!(w, "#ifndef __RequestUnion__{s}__defined")?;
    writeln!(w, "#define __RequestUnion__{s}__defined")?;
    writeln!(w, "union __RequestUnion__{s} {{")?;
    for rt in g.routines {
        writeln!(w, "\t__Request__{}_t Request_{};", rt.name, rt.name)?;
    }
    writeln!(w, "}};")?;
    writeln!(w, "#endif /* __RequestUnion__{s}__defined */")
}

/// `WriteServerReplyUnion`
pub fn write_server_reply_union(w: &mut dyn Write, g: &Gen) -> io::Result<()> {
    let s = g.server_subsys();
    writeln!(w)?;
    writeln!(w, "/* union of all replies */")?;
    writeln!(w)?;
    writeln!(w, "#ifndef __ReplyUnion__{s}__defined")?;
    writeln!(w, "#define __ReplyUnion__{s}__defined")?;
    writeln!(w, "union __ReplyUnion__{s} {{")?;
    for rt in g.routines {
        writeln!(w, "\t__Reply__{}_t Reply_{};", rt.name, rt.name)?;
    }
    writeln!(w, "}};")?;
    writeln!(w, "#endif /* __ReplyUnion__{s}__defined */")
}

/// `WriteServerHeader`
pub fn write_server_header(w: &mut dyn Write, g: &Gen) -> io::Result<()> {
    let protect = format!("{}_server_", g.subsystem());
    write_prolog(w, g, Some(&protect), true, false)?;
    for stmt in g.stmts {
        if let Statement::Import { kind, filename } = stmt {
            if matches!(
                kind,
                ImportKind::Import | ImportKind::SImport | ImportKind::DImport
            ) {
                write_import(w, filename)?;
            }
        }
    }
    writeln!(w, "\n#ifdef __BeforeMigServerHeader")?;
    writeln!(w, "__BeforeMigServerHeader")?;
    writeln!(w, "#endif /* __BeforeMigServerHeader */\n")?;
    write_bogus_server_routine_annotation_define(w)?;
    for rt in g.routines {
        write_server_routine(w, g, rt)?;
    }
    write_dispatcher(w, g)?;
    write_request_types(w, g)?;
    write_server_request_union(w, g)?;
    write_reply_types(w, g)?;
    write_server_reply_union(w, g)?;
    write_epilog(w, g, Some(&protect), false)
}

/// `WriteInternalHeader`
pub fn write_internal_header(w: &mut dyn Write, g: &Gen) -> io::Result<()> {
    for rt in g.routines {
        writeln!(w, "#define {} {}_external", rt.user_name, rt.user_name)?;
    }
    Ok(())
}

/// `WriteDefinesHeader`
pub fn write_defines_header(w: &mut dyn Write, g: &Gen) -> io::Result<()> {
    let protect = format!("{}_defines", g.subsystem());
    write_prolog(w, g, Some(&protect), false, false)?;
    writeln!(
        w,
        "\n/*\tDefines related to the Subsystem {}\t*/\n",
        g.subsystem()
    )?;
    for rt in g.routines {
        let up = rt.name.to_uppercase();
        let id = rt.number + g.opts.subsystem_base;
        writeln!(w, "#define\tMACH_ID_{up}\t\t{id}\t/* {}() */", rt.name)?;
        if rt.kind == crate::ast::RoutineKind::Routine {
            writeln!(
                w,
                "#define\tMACH_ID_{up}_REPLY\t\t{}\t/* {}() */",
                id + 100,
                rt.name
            )?;
        }
        writeln!(w)?;
    }
    write_epilog(w, g, Some(&protect), false)
}
