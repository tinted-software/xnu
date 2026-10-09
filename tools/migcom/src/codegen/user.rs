// SPDX-License-Identifier: MIT
// User-side message packing and reply decoding, following migcom.tproj/user.c.

use std::io::{self, Write};

use super::utils::{self, Spelling};
use super::Gen;
use crate::ast::ConsumeOnSendError;
use crate::routine::{ak, Arg, Dealloc, Kpd, Routine};
use crate::types::{fl, ipc_type_num::MACH_MSG_TYPE_POLYMORPHIC, IpcType};

pub fn write_user(w: &mut dyn Write, g: &Gen) -> io::Result<()> {
    prolog(w, g)?;
    for rt in g.routines {
        write_routine(w, g, rt)?;
    }
    Ok(())
}

pub fn write_user_individual(w: &mut dyn Write, g: &Gen, rt: &Routine) -> io::Result<()> {
    prolog(w, g)?;
    write_routine(w, g, rt)
}

fn prolog(w: &mut dyn Write, g: &Gen) -> io::Result<()> {
    utils::write_identification(w, g.opts)?;
    writeln!(w, "\n/* Module {} */", g.subsystem())?;
    writeln!(
        w,
        "#define __MIG_check__Reply__{}_subsystem__ 1",
        g.subsystem()
    )?;
    if g.opts.check_ndr {
        writeln!(
            w,
            "#define __NDR_convert__Reply__{}_subsystem__ 1",
            g.subsystem()
        )?;
        writeln!(w, "#define __NDR_convert__mig_reply_error_subsystem__ 1")?;
    }
    utils::write_bogus_defines(w)?;
    utils::write_includes(w, g, true, false)?;
    if let Some(h) = &g.opts.user_header_filename {
        writeln!(w, "#include \"{}\"", utils::base_name(h))?;
    }
    utils::write_impl_imports(w, g.stmts, true)?;
    if g.opts.has_consume_on_send_error && !g.opts.is_kernel_user {
        writeln!(w, "#include <mach/mach.h>")?;
    }
    if g.opts.has_use_special_reply_port {
        writeln!(w, "#include <TargetConditionals.h>\n#include <mach/mach_sync_ipc.h>\n#ifndef __MigSpecialReplyPortMsgOption\n#define __MigSpecialReplyPortMsgOption (MACH_SEND_SYNC_OVERRIDE|MACH_SEND_SYNC_USE_THRPRI|MACH_RCV_SYNC_WAIT)\n#endif")?;
    }
    writeln!(w, "#ifdef __cplusplus\nextern \"C\" {{\n#endif\nextern void mach_msg_destroy(mach_msg_header_t *);\n#ifdef __cplusplus\n}}\n#endif")?;
    writeln!(
        w,
        "#define msgh_request_port msgh_remote_port\n#define msgh_reply_port msgh_local_port"
    )?;
    if let Some(rcs) = &g.opts.rcs_id {
        utils::write_rcs_decl(w, &format!("{}_user", g.subsystem()), rcs)?;
    }
    utils::write_appl_defaults(w, "Send")
}

fn value(a: &Arg) -> String {
    if a.by_reference_user {
        format!("(*{})", a.var_name())
    } else {
        a.var_name().to_string()
    }
}

fn return_error(w: &mut dyn Write, _g: &Gen, rt: &Routine, error: &str) -> io::Result<()> {
    utils::write_return_msg_error(w, rt, true, error)
}
fn body_field(a: &Arg, request: bool) -> String {
    format!(
        "{}{}P->{}",
        if request { "In" } else { "Out" },
        if request { a.request_pos } else { a.reply_pos },
        a.msg_field()
    )
}

fn reply_type(rt: &Routine) -> String {
    format!("__MigReply__{}_t", rt.name)
}

fn capacity(g: &Gen, a: &Arg) -> u32 {
    let t = &g.types[a.ty];
    if t.is_multiple_kpd() {
        t.kpd_number
    } else {
        t.number / t.element.map(|e| g.types[e].number).unwrap_or(1).max(1)
    }
}

fn variable_max(g: &Gen, a: &Arg) -> String {
    let t = &g.types[a.ty];
    if t.is_optional_native() {
        format!("_WALIGNSZ_({})", t.user_type())
    } else {
        (t.type_size + t.pad_size).to_string()
    }
}

// Use the C layout for the fixed portion; descriptor sizes differ between
// user-space and kernel builds, while inline variable fields remain 4-aligned.
fn minimum(g: &Gen, rt: &Routine, mask: u32, name: &str) -> String {
    let mut s = format!("(mach_msg_size_t)(sizeof({name})");
    for a in rt.iter().filter(|a| a.has_all(mask | ak::VARIABLE)) {
        s.push_str(&format!(" - {}", variable_max(g, a)));
    }
    s.push(')');
    s
}

fn variable_size(g: &Gen, rt: &Routine, a: &Arg, request: bool) -> String {
    let t = &g.types[a.ty];
    if t.is_optional_native() {
        return format!(
            "({}{}P->__Present__{} ? _WALIGNSZ_({}) : 0)",
            if request { "In" } else { "Out" },
            if request { a.request_pos } else { a.reply_pos },
            a.msg_field(),
            t.user_type()
        );
    }
    let count = &rt[a.count.expect("variable array has count")];
    let bytes = g.types[t.element.expect("variable array has element")].type_size;
    format!("_WALIGN_({} * {bytes})", body_field(count, request))
}

fn disposition(rt: &Routine, g: &Gen, a: &Arg) -> String {
    if g.types[a.ty].in_name == MACH_MSG_TYPE_POLYMORPHIC {
        value(&rt[a.poly.expect("polymorphic argument has disposition")])
    } else {
        g.types[a.ty].in_name_str().to_string()
    }
}

fn descriptor_type(kpd: Kpd) -> &'static str {
    match kpd {
        Kpd::Port => "MACH_MSG_PORT_DESCRIPTOR",
        Kpd::Ool => "MACH_MSG_OOL_DESCRIPTOR",
        Kpd::OolPorts => "MACH_MSG_OOL_PORTS_DESCRIPTOR",
    }
}

fn descriptor_data<'a>(g: &'a Gen, a: &Arg) -> &'a IpcType {
    let t = &g.types[a.ty];
    if t.is_multiple_kpd() {
        &g.types[t.element.expect("multiple descriptor has element")]
    } else {
        t
    }
}

fn descriptor_extent(g: &Gen, rt: &Routine, a: &Arg, request: bool, index: &str) -> String {
    let t = descriptor_data(g, a);
    let multiple = g.types[a.ty].is_multiple_kpd();
    if t.var_array {
        let c = &rt
            [if multiple { a.sub_count } else { a.count }.expect("variable descriptor has count")];
        let count = if request {
            value(c)
        } else {
            body_field(c, false)
        };
        let multiplier = if a.kpd == Some(Kpd::OolPorts) {
            1
        } else {
            (c.multiplier * t.size / 8).max(1)
        };
        format!("({count}{index} * {multiplier})")
    } else if a.kpd == Some(Kpd::OolPorts) {
        t.number.to_string()
    } else {
        ((t.number * t.size + 7) / 8).to_string()
    }
}

fn pack_descriptor(w: &mut dyn Write, g: &Gen, rt: &Routine, a: &Arg) -> io::Result<()> {
    let t = &g.types[a.ty];
    let kpd = a.kpd.expect("descriptor kind");
    let multiple = t.is_multiple_kpd();
    let index = if multiple { "[i]" } else { "" };
    let dest = format!("In0P->{}{index}", a.msg_field());
    if multiple {
        if t.var_array {
            writeln!(
                w,
                "\tif ({} > {})",
                value(&rt[a.count.expect("descriptor count")]),
                t.kpd_number
            )?;
            return_error(w, g, rt, "MIG_ARRAY_TOO_LARGE")?;
        }
        writeln!(
            w,
            "\tfor (unsigned int i = 0; i < {}; ++i) {{",
            t.kpd_number
        )?;
    }
    writeln!(w, "\tmemset(&{dest}, 0, sizeof({dest}));")?;
    writeln!(w, "\t{dest}.type = {};", descriptor_type(kpd))?;
    if multiple && t.var_array {
        writeln!(
            w,
            "\tif (i < {}) {{",
            value(&rt[a.count.expect("descriptor count")])
        )?;
    }
    let src = format!("{}{index}", value(a));
    match kpd {
        Kpd::Port => {
            writeln!(w, "\t{dest}.name = (mach_port_t){src};")?;
            writeln!(w, "\t{dest}.disposition = {};", disposition(rt, g, a))?;
        }
        Kpd::Ool | Kpd::OolPorts => {
            writeln!(w, "\t{dest}.address = (void *){src};")?;
            writeln!(
                w,
                "\t{dest}.{} = {};",
                if kpd == Kpd::Ool { "size" } else { "count" },
                descriptor_extent(g, rt, a, true, index)
            )?;
            let dealloc = match a.deallocate {
                Dealloc::No => "FALSE".to_string(),
                Dealloc::Yes => "TRUE".to_string(),
                Dealloc::Maybe => value(&rt[a.dealloc.expect("conditional deallocation arg")]),
            };
            writeln!(w, "\t{dest}.deallocate = {dealloc};")?;
            writeln!(
                w,
                "\t{dest}.copy = {};",
                if a.flags & fl::PHYSICAL_COPY != 0 {
                    "MACH_MSG_PHYSICAL_COPY"
                } else {
                    "MACH_MSG_VIRTUAL_COPY"
                }
            )?;
            if kpd == Kpd::OolPorts {
                writeln!(w, "\t{dest}.disposition = {};", disposition(rt, g, a))?;
            }
        }
    }
    if multiple && t.var_array {
        writeln!(w, "\t}}")?;
    }
    if multiple {
        writeln!(w, "\t}}")?;
    }
    Ok(())
}

fn pack_body(w: &mut dyn Write, g: &Gen, rt: &Routine, a: &Arg) -> io::Result<()> {
    let t = &g.types[a.ty];
    let dst = body_field(a, true);
    let src = if t.native_pointer {
        format!("(*{})", a.var_name())
    } else {
        value(a)
    };
    if a.ident() == ak::E_NDR_CODE {
        writeln!(w, "\t{dst} = NDR_record;")?;
    } else if a.ident() == ak::E_COUNT_IN_OUT {
        let c = &rt[a.cinout.expect("count in out twin")];
        let parent = &rt[c.parent.expect("count parent")];
        writeln!(w, "\t{dst} = min({}, {});", value(c), capacity(g, parent))?;
    } else if t.is_string && t.var_array {
        let count = body_field(&rt[a.count.expect("string count")], true);
        writeln!(w, "#ifdef USING_MIG_STRNCPY_ZEROFILL\n\tif (mig_strncpy_zerofill != NULL)\n\t\t{count} = mig_strncpy_zerofill({dst}, {}, {});\n\telse\n#endif\n\t\t{count} = mig_strncpy({dst}, {}, {});", a.var_name(), t.number, a.var_name(), t.number)?;
        writeln!(w, "\tIn{}P->{}Offset = 0;", a.request_pos, a.msg_field())?;
    } else if t.is_variable_sized_untyped() {
        let c = &rt[a.count.expect("inline count")];
        writeln!(w, "\tif ({} > {})", value(c), capacity(g, a))?;
        return_error(w, g, rt, "MIG_ARRAY_TOO_LARGE")?;
        if a.flags & fl::SAME_COUNT == 0 {
            writeln!(w, "\t{} = {};", body_field(c, true), value(c))?;
        }
        writeln!(
            w,
            "\tmemcpy({dst}, {src}, {} * {});",
            value(c),
            g.types[t.element.expect("array element")].type_size
        )?;
    } else if t.is_optional_native() {
        writeln!(
            w,
            "\tif ((In{}P->__Present__{} = ({} != {}))) {{",
            a.request_pos,
            a.msg_field(),
            a.var_name(),
            t.bad_value.as_deref().expect("optional native bad value")
        )?;
        utils::write_copy_type(
            w,
            t,
            true,
            &format!("{dst}.__Real__{}", a.msg_field()),
            &src,
        )?;
        writeln!(w, "\t}}")?;
    } else {
        utils::write_copy_type(w, t, true, &dst, &src)?;
    }
    if t.is_variable_sized_untyped() {
        let c = &rt[a.count.expect("inline array count")];
        let bytes = g.types[t.element.expect("inline array element")].type_size;
        if bytes % 4 != 0 {
            let length = format!("({} * {bytes})", body_field(c, true));
            writeln!(
                w,
                "\tmemset((char *){dst} + {length}, 0, _WALIGN_({length}) - {length});"
            )?;
        }
    }
    if t.pad_size != 0 {
        writeln!(
            w,
            "\tmemset(In{}P->{}, 0, {});",
            a.request_pos, a.pad_name, t.pad_size
        )?;
    }
    Ok(())
}

fn ndr_macro(rt: &Routine, a: &Arg, rep: &str) -> String {
    format!(
        "__NDR_convert__{rep}__Reply__{}_t__{}",
        rt.name,
        a.msg_field()
    )
}

fn ndr_declarations(w: &mut dyn Write, g: &Gen, rt: &Routine) -> io::Result<()> {
    for a in rt.iter().filter(|a| a.has(ak::RETURN_NDR)) {
        for rep in ["int_rep", "char_rep", "float_rep"] {
            if rep != "int_rep"
                && matches!(a.ident(), ak::E_COUNT | ak::E_COUNT_IN_OUT | ak::E_RET_CODE)
            {
                continue;
            }
            let mac = ndr_macro(rt, a, rep);
            writeln!(w, "#ifndef {mac}__defined")?;
            let mut ty = a.ty;
            let mut prev = a.ty;
            let mut multiplier = if a.parent.is_none() { a.multiplier } else { 1 };
            let mut arrays = 0;
            let mut first = true;
            loop {
                let t = &g.types[ty];
                let p = &g.types[prev];
                if t.number < p.number && !p.var_array && a.parent.is_none() {
                    multiplier *= p.number / t.number.max(1);
                }
                if t.var_array {
                    arrays += 1;
                }
                let spelling = t.server_type();
                if !spelling.is_empty() && !(ty != prev && arrays != 0 && p.var_array) {
                    for domain in [format!("__{}", g.subsystem()), String::new()] {
                        let conv = format!("__NDR_convert__{rep}{domain}__{spelling}");
                        writeln!(
                            w,
                            "#{} defined({conv}__defined)",
                            if first { "if" } else { "elif" }
                        )?;
                        first = false;
                        writeln!(w, "#define {mac}__defined")?;
                        let carg = if a.count.is_some() { ", c" } else { "" };
                        let call = if arrays != 0 {
                            format!(
                                "__NDR_convert__ARRAY(({spelling} *)(a), f, {} * (c), {conv})",
                                multiplier
                            )
                        } else if multiplier > 1 && !t.is_string {
                            format!(
                                "__NDR_convert__ARRAY(({spelling} *)(a), f, {multiplier}, {conv})"
                            )
                        } else {
                            format!("{conv}(({spelling} *)(a), f{carg})")
                        };
                        writeln!(w, "#define {mac}(a, f{carg}) {call}")?;
                    }
                }
                let Some(element) = t.element else {
                    break;
                };
                prev = ty;
                ty = element;
            }
            if !first {
                writeln!(w, "#endif")?;
            }
            writeln!(w, "#endif")?;
        }
    }
    Ok(())
}

fn ndr_use(w: &mut dyn Write, rt: &Routine, a: &Arg, rep: &str) -> io::Result<()> {
    let mac = ndr_macro(rt, a, rep);
    writeln!(w, "#if defined({mac}__defined)")?;
    writeln!(w, "\tif (Out0P->NDR.{rep} != NDR_record.{rep})")?;
    let ptr = if a.kpd == Some(Kpd::Ool) {
        format!("Out0P->{}.address", a.msg_field())
    } else {
        format!("&{}", body_field(a, false))
    };
    write!(w, "\t\t{mac}({ptr}, Out0P->NDR.{rep}")?;
    if let Some(c) = a.count {
        write!(w, ", {}", body_field(&rt[c], false))?;
    }
    writeln!(w, ");\n#endif")
}

fn write_checker(w: &mut dyn Write, g: &Gen, rt: &Routine) -> io::Result<()> {
    let name = reply_type(rt);
    utils::write_struct_decl(
        w,
        g,
        rt,
        Spelling::User,
        ak::REPLY,
        &name,
        rt.simple_reply,
        false,
        false,
        false,
    )?;
    if g.opts.check_ndr && rt.ndr_code().has(ak::REPLY) {
        ndr_declarations(w, g, rt)?;
    }
    writeln!(
        w,
        "#ifndef __MIG_check__Reply__{}_t__defined\n#define __MIG_check__Reply__{}_t__defined",
        rt.name, rt.name
    )?;
    write!(
        w,
        "mig_internal kern_return_t __MIG_check__Reply__{}_t({name} *Out0P",
        rt.name
    )?;
    for pos in 1..=rt.max_reply_pos {
        write!(w, ", {name} **Out{pos}PP")?;
    }
    writeln!(w, ")\n{{")?;
    for pos in 1..=rt.max_reply_pos {
        writeln!(w, "\t{name} *Out{pos}P;")?;
    }
    writeln!(w, "\tmach_msg_size_t msgh_size = Out0P->Head.msgh_size;")?;
    if rt.num_reply_var != 0 {
        writeln!(w, "\tmach_msg_size_t msgh_size_delta;")?;
    }
    writeln!(w, "\tif (Out0P->Head.msgh_id != {})\n\t\treturn Out0P->Head.msgh_id == MACH_NOTIFY_SEND_ONCE ? MIG_SERVER_DIED : MIG_REPLY_MISMATCH;", g.opts.subsystem_base + rt.number + 100)?;
    writeln!(w, "#if __MigTypeCheck\n\tif (Out0P->Head.msgh_remote_port != MACH_PORT_NULL)\n\t\treturn MIG_TYPE_ERROR;\n#endif")?;
    // Error replies are always simple, even when the normal reply has KPDs.
    writeln!(w, "\tif (!(Out0P->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) && msgh_size == sizeof(mig_reply_error_t)) {{")?;
    if g.opts.check_ndr {
        writeln!(w, "#ifdef __NDR_convert__mig_reply_error_t__defined\n\t\t__NDR_convert__mig_reply_error_t((mig_reply_error_t *)Out0P);\n#endif")?;
    }
    writeln!(w, "\t\tif (((mig_reply_error_t *)Out0P)->RetCode != KERN_SUCCESS)\n\t\t\treturn ((mig_reply_error_t *)Out0P)->RetCode;")?;
    if !rt.simple_reply || !rt.no_reply_args {
        writeln!(w, "\t\treturn MIG_TYPE_ERROR;")?;
    }
    writeln!(w, "\t}}")?;
    let min = minimum(g, rt, ak::REPLY, &name);
    // Bounds are necessary for safe shifted-pointer calculations, independently
    // of optional descriptor type checking.
    writeln!(
        w,
        "\tif (msgh_size < {min} || msgh_size > sizeof({name}))\n\t\treturn MIG_TYPE_ERROR;"
    )?;
    if rt.simple_reply {
        writeln!(w, "#if __MigTypeCheck\n\tif (Out0P->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX)\n\t\treturn MIG_TYPE_ERROR;\n#endif")?;
    } else {
        writeln!(w, "\tif (!(Out0P->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) || Out0P->msgh_body.msgh_descriptor_count != {})\n\t\treturn MIG_TYPE_ERROR;", rt.reply_kpds)?;
    }
    if rt.ret_code().has(ak::REPLY) {
        if g.opts.check_ndr {
            ndr_use(w, rt, rt.ret_code(), "int_rep")?;
        }
        writeln!(
            w,
            "\tif (Out0P->{} != KERN_SUCCESS)\n\t\treturn Out0P->{};",
            rt.ret_code().msg_field(),
            rt.ret_code().msg_field()
        )?;
    }
    writeln!(w, "\tmach_msg_size_t expected_size = {min};")?;
    for a in rt.iter().filter(|a| a.has_all(ak::REPLY | ak::RETURN_BODY)) {
        if !a.has(ak::VARIABLE) {
            continue;
        }
        let t = &g.types[a.ty];
        if t.is_variable_sized_untyped() {
            let c = &rt[a.count.expect("reply count")];
            if g.opts.check_ndr && a.same_count.is_none() {
                ndr_use(w, rt, c, "int_rep")?;
            }
            writeln!(
                w,
                "\tif ({} > {})\n\t\treturn MIG_TYPE_ERROR;",
                body_field(c, false),
                capacity(g, a)
            )?;
        }
        writeln!(w, "\tmsgh_size_delta = {};", variable_size(g, rt, a, false))?;
        writeln!(w, "\tif (msgh_size_delta > msgh_size - expected_size)\n\t\treturn MIG_TYPE_ERROR;\n\texpected_size += msgh_size_delta;")?;
        if t.is_string {
            let c = &rt[a.count.expect("string count")];
            writeln!(
                w,
                "\tif ({} == 0 || {}[{} - 1] != 0)\n\t\treturn MIG_TYPE_ERROR;",
                body_field(c, false),
                body_field(a, false),
                body_field(c, false)
            )?;
        }
        if a.reply_pos < rt.max_reply_pos {
            writeln!(
                w,
                "\t*Out{}PP = Out{}P = ({name} *)((char *)Out{}P + msgh_size_delta - {});",
                a.reply_pos + 1,
                a.reply_pos + 1,
                a.reply_pos,
                variable_max(g, a)
            )?;
        }
    }
    writeln!(
        w,
        "\tif (msgh_size != expected_size)\n\t\treturn MIG_TYPE_ERROR;"
    )?;
    if g.opts.check_ndr && rt.ndr_code().has(ak::REPLY) {
        for a in rt.iter().filter(|a| a.has(ak::RETURN_NDR)) {
            if matches!(a.ident(), ak::E_COUNT | ak::E_COUNT_IN_OUT | ak::E_RET_CODE) {
                if a.parent
                    .map(|p| g.types[rt[p].ty].is_variable_sized_untyped())
                    .unwrap_or(false)
                    || a.ident() == ak::E_RET_CODE
                {
                    continue;
                }
            }
            for rep in ["int_rep", "char_rep", "float_rep"] {
                if rep != "int_rep" && matches!(a.ident(), ak::E_COUNT | ak::E_COUNT_IN_OUT) {
                    continue;
                }
                ndr_use(w, rt, a, rep)?;
            }
        }
    }
    for a in rt.iter().filter(|a| a.has(ak::RETURN_KPD)) {
        check_descriptor(w, g, rt, a)?;
    }
    writeln!(w, "\treturn MACH_MSG_SUCCESS;\n}}\n#endif")
}

fn check_descriptor(w: &mut dyn Write, g: &Gen, rt: &Routine, a: &Arg) -> io::Result<()> {
    let t = &g.types[a.ty];
    let data = descriptor_data(g, a);
    let kpd = a.kpd.expect("reply descriptor kind");
    let index = if t.is_multiple_kpd() { "[i]" } else { "" };
    let field = format!("Out0P->{}{index}", a.msg_field());
    writeln!(w, "#if __MigTypeCheck")?;
    if t.is_multiple_kpd() {
        writeln!(
            w,
            "\tfor (unsigned int i = 0; i < {}; ++i) {{",
            t.kpd_number
        )?;
    }
    writeln!(
        w,
        "\tif ({field}.type != {})\n\t\treturn MIG_TYPE_ERROR;",
        descriptor_type(kpd)
    )?;
    if t.is_multiple_kpd() && t.var_array && kpd != Kpd::Port {
        let count = body_field(&rt[a.count.expect("descriptor array count")], false);
        let extent = if kpd == Kpd::Ool { "size" } else { "count" };
        writeln!(w, "\tif (i >= {count}) {{\n\t\tif ({field}.{extent} != 0)\n\t\t\treturn MIG_TYPE_ERROR;\n\t\tcontinue;\n\t}}")?;
    }
    if a.poly.is_none() && (kpd == Kpd::OolPorts || (kpd == Kpd::Port && !t.var_array)) {
        writeln!(
            w,
            "\tif ({field}.disposition != {})\n\t\treturn MIG_TYPE_ERROR;",
            data.out_name_str()
        )?;
    }
    if kpd != Kpd::Port {
        let extent = if kpd == Kpd::Ool { "size" } else { "count" };
        if !t.var_array || data.var_array {
            if data.var_array && kpd == Kpd::Ool {
                let c = &rt[if t.is_multiple_kpd() {
                    a.sub_count
                } else {
                    a.count
                }
                .expect("OOL count")];
                let factor = (c.multiplier * data.size / 8).max(1);
                writeln!(w, "\tif ({field}.size / {factor} != {}{index} || {field}.size % {factor} != 0)\n\t\treturn MIG_TYPE_ERROR;", body_field(c, false))?;
            } else {
                let exp = descriptor_extent(g, rt, a, false, index);
                writeln!(
                    w,
                    "\tif ({field}.{extent} != {exp})\n\t\treturn MIG_TYPE_ERROR;"
                )?;
            }
        }
        if data.var_array && data.ool_number != 0 {
            let c = &rt[if t.is_multiple_kpd() {
                a.sub_count
            } else {
                a.count
            }
            .expect("OOL count")];
            writeln!(
                w,
                "\tif ({}{index} > {})\n\t\treturn MIG_TYPE_ERROR;",
                body_field(c, false),
                data.ool_number
            )?;
        }
    }
    if t.is_multiple_kpd() {
        writeln!(w, "\t}}")?;
    }
    if t.var_array && t.is_multiple_kpd() {
        writeln!(
            w,
            "\tif ({} > {})\n\t\treturn MIG_TYPE_ERROR;",
            body_field(&rt[a.count.expect("multiple descriptor count")], false),
            t.kpd_number
        )?;
    }
    writeln!(w, "#endif")
}

fn destroy(w: &mut dyn Write, g: &Gen, ptr: &str) -> io::Result<()> {
    if g.opts.is_kernel_user {
        writeln!(w, "#if __MigKernelSpecificCode\n\tmach_msg_destroy_from_kernel(&{ptr}->Head);\n#else\n\tmach_msg_destroy(&{ptr}->Head);\n#endif")
    } else {
        writeln!(w, "\tmach_msg_destroy(&{ptr}->Head);")
    }
}

fn send_cleanup(w: &mut dyn Write, g: &Gen, rt: &Routine) -> io::Result<()> {
    if rt.consume_on_send_error != ConsumeOnSendError::Any && rt.wait_time.is_none() {
        return Ok(());
    }
    let cond = if rt.consume_on_send_error == ConsumeOnSendError::Any {
        "msg_result == MACH_SEND_INVALID_DEST || msg_result == MACH_SEND_TIMED_OUT"
    } else {
        "msg_result == MACH_SEND_TIMED_OUT"
    };
    writeln!(w, "\tif ({cond}) {{")?;
    if rt.consume_on_send_error == ConsumeOnSendError::None {
        for a in rt
            .iter()
            .filter(|a| a.has(ak::SEND_KPD) && a.kpd == Some(Kpd::Ool))
        {
            let t = &g.types[a.ty];
            let index = if t.is_multiple_kpd() { "[i]" } else { "" };
            if t.is_multiple_kpd() {
                writeln!(
                    w,
                    "\tfor (unsigned int i = 0; i < {}; ++i) {{",
                    if t.var_array {
                        value(&rt[a.count.expect("count")])
                    } else {
                        t.kpd_number.to_string()
                    }
                )?;
            }
            let desc = format!("In0P->{}{index}", a.msg_field());
            writeln!(w, "\tif ((vm_offset_t){desc}.address != (vm_offset_t){}{index})\n\t\tmig_deallocate((vm_offset_t){desc}.address, (vm_size_t){desc}.size);", value(a))?;
            if t.is_multiple_kpd() {
                writeln!(w, "\t}}")?;
            }
        }
    } else {
        if !g.opts.is_kernel_user {
            writeln!(w, "\tif (MACH_MSGH_BITS_LOCAL(In0P->Head.msgh_bits) == MACH_MSG_TYPE_MOVE_SEND)\n\t\tmach_port_deallocate(mach_task_self(), In0P->Head.msgh_local_port);")?;
        }
        destroy(w, g, "In0P")?;
    }
    writeln!(w, "\t}}")
}

fn receive_cleanup(w: &mut dyn Write, rt: &Routine) -> io::Result<()> {
    if rt.reply_port().has(ak::USER_ARG) {
        return Ok(());
    }
    writeln!(w, "\tif (msg_result != MACH_MSG_SUCCESS) {{\n\t\tswitch (msg_result) {{\n\t\tcase MACH_SEND_INVALID_DATA:\n\t\tcase MACH_SEND_INVALID_DEST:\n\t\tcase MACH_SEND_INVALID_HEADER:")?;
    if !rt.use_special_reply_port {
        writeln!(w, "\t\t\tmig_put_reply_port(reply_port);")?;
    }
    writeln!(w, "\t\t\tbreak;\n\t\tdefault:")?;
    writeln!(
        w,
        "\t\t\t{}(reply_port);\n\t\t}}\n\t}}",
        if rt.use_special_reply_port {
            "mig_dealloc_special_reply_port"
        } else {
            "mig_dealloc_reply_port"
        }
    )
}

fn overwrite_template(w: &mut dyn Write, g: &Gen, rt: &Routine) -> io::Result<()> {
    writeln!(w, "\tmemset(InOvTemplate, 0, sizeof(*InOvTemplate));\n\tInOvTemplate->msgh_body.msgh_descriptor_count = {};", rt.overwrite_kpds)?;
    for a in rt.iter().filter(|a| a.has(ak::OVERWRITE)) {
        let t = &g.types[a.ty];
        let index = if t.is_multiple_kpd() { "[i]" } else { "" };
        let dest = format!("InOvTemplate->{}{index}", a.msg_field());
        if t.is_multiple_kpd() {
            writeln!(
                w,
                "\tfor (unsigned int i = 0; i < {}; ++i) {{",
                t.kpd_number
            )?;
        }
        writeln!(
            w,
            "\t{dest}.type = {};\n\t{dest}.copy = MACH_MSG_ALLOCATE;",
            descriptor_type(a.kpd.expect("overwrite KPD"))
        )?;
        if a.flags & fl::OVERWRITE != 0 {
            if t.is_multiple_kpd() && t.var_array {
                writeln!(
                    w,
                    "\tif (i < {}) {{",
                    value(&rt[a.count.expect("overwrite count")])
                )?;
            }
            writeln!(
                w,
                "\t{dest}.address = (void *){}{index};\n\t{dest}.copy = MACH_MSG_OVERWRITE;",
                value(a)
            )?;
            writeln!(
                w,
                "\t{dest}.{} = {};",
                if a.kpd == Some(Kpd::OolPorts) {
                    "count"
                } else {
                    "size"
                },
                descriptor_extent(g, rt, a, true, index)
            )?;
            if t.is_multiple_kpd() && t.var_array {
                writeln!(w, "\t}}")?;
            }
        }
        if t.is_multiple_kpd() {
            writeln!(w, "\t}}")?;
        }
    }
    Ok(())
}

fn write_transport(w: &mut dyn Write, g: &Gen, rt: &Routine) -> io::Result<()> {
    let option = rt.msg_option().var_name();
    let timeout = rt
        .wait_time()
        .map(value)
        .unwrap_or_else(|| "MACH_MSG_TIMEOUT_NONE".to_string());
    let send_timeout = if rt.wait_time.is_some() {
        "MACH_SEND_TIMEOUT|"
    } else {
        ""
    };
    let rcv_timeout = if rt
        .wait_time()
        .map(|a| a.ident() == ak::E_WAIT_TIME)
        .unwrap_or(false)
    {
        "MACH_RCV_TIMEOUT|"
    } else {
        ""
    };
    let trailer = if rt.user_impl != 0 {
        "MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0)|"
    } else {
        ""
    };
    if rt.one_way {
        if g.opts.is_kernel_user {
            writeln!(w, "#if __MigKernelSpecificCode\n\tmsg_result = mach_msg_send_from_kernel(&In0P->Head, msgh_size);\n#else")?;
        }
        writeln!(w, "\tmsg_result = mach_msg(&In0P->Head, MACH_SEND_MSG|{send_timeout}{option}, msgh_size, 0, MACH_PORT_NULL, {timeout}, MACH_PORT_NULL);")?;
        if g.opts.is_kernel_user {
            writeln!(w, "#endif")?;
        }
    } else {
        if rt.overwrite != 0 && g.opts.use_msg_rpc {
            overwrite_template(w, g, rt)?;
        }
        if g.opts.is_kernel_user {
            writeln!(w, "#if __MigKernelSpecificCode\n\tmsg_result = mach_msg_rpc_from_kernel(&In0P->Head, msgh_size, (mach_msg_size_t)sizeof(Reply));\n#else")?;
        }
        if g.opts.use_msg_rpc {
            if rt.overwrite != 0 {
                writeln!(w, "\tmsg_result = mach_msg_overwrite(&In0P->Head, MACH_SEND_MSG|MACH_RCV_MSG|MACH_RCV_OVERWRITE|{send_timeout}{rcv_timeout}{trailer}{option}, msgh_size, (mach_msg_size_t)sizeof(Reply), reply_port, {timeout}, MACH_PORT_NULL, &InOvTemplate->Head, (mach_msg_size_t)sizeof(OverwriteTemplate));")?;
            } else {
                writeln!(w, "\tmsg_result = mach_msg(&In0P->Head, MACH_SEND_MSG|MACH_RCV_MSG|{send_timeout}{rcv_timeout}{trailer}{option}, msgh_size, (mach_msg_size_t)sizeof(Reply), reply_port, {timeout}, MACH_PORT_NULL);")?;
            }
        } else {
            writeln!(w, "\tmsg_result = mach_msg(&In0P->Head, MACH_SEND_MSG|{send_timeout}{option}, msgh_size, 0, MACH_PORT_NULL, {timeout}, MACH_PORT_NULL);")?;
            send_cleanup(w, g, rt)?;
            writeln!(w, "\tif (msg_result != MACH_MSG_SUCCESS)")?;
            return_error(w, g, rt, "msg_result")?;
            writeln!(w, "\tmsg_result = mach_msg(&Out0P->Head, MACH_RCV_MSG|{rcv_timeout}{trailer}{option}, 0, (mach_msg_size_t)sizeof(Reply), reply_port, {}, MACH_PORT_NULL);", if rcv_timeout.is_empty() { "MACH_MSG_TIMEOUT_NONE" } else { &timeout })?;
        }
        if g.opts.is_kernel_user {
            writeln!(w, "#endif")?;
        }
        receive_cleanup(w, rt)?;
    }
    utils::write_appl_macro(w, g, "Send", "After", rt)?;
    send_cleanup(w, g, rt)?;
    writeln!(w, "\tif (msg_result != MACH_MSG_SUCCESS)")?;
    return_error(w, g, rt, "msg_result")
}

fn extract_descriptor(w: &mut dyn Write, g: &Gen, rt: &Routine, a: &Arg) -> io::Result<()> {
    let t = &g.types[a.ty];
    let kpd = a.kpd.expect("returned descriptor");
    let index = if t.is_multiple_kpd() { "[i]" } else { "" };
    let desc = format!("Out0P->{}{index}", a.msg_field());
    if t.is_multiple_kpd() {
        let limit = if t.var_array {
            format!(
                "min({}, {})",
                body_field(&rt[a.count.expect("count")], false),
                if a.count_in_out {
                    value(&rt[a.count.expect("count")])
                } else {
                    capacity(g, a).to_string()
                }
            )
        } else {
            t.kpd_number.to_string()
        };
        writeln!(w, "\tfor (unsigned int i = 0; i < {limit}; ++i) {{")?;
    }
    let ty = descriptor_data(g, a).user_type();
    writeln!(
        w,
        "\t{}{index} = ({ty}){desc}.{};",
        value(a),
        if kpd == Kpd::Port { "name" } else { "address" }
    )?;
    if t.is_multiple_kpd() {
        writeln!(w, "\t}}")?;
    }
    if let Some(p) = a.poly {
        if rt[p].has(ak::RETURN_RCV) {
            writeln!(
                w,
                "\t{} = Out0P->{}{}.disposition;",
                value(&rt[p]),
                a.msg_field(),
                if t.is_multiple_kpd() { "[0]" } else { "" }
            )?;
        }
    }
    if t.is_multiple_kpd() && t.var_array {
        let c = &rt[a.count.expect("count")];
        let max = if a.count_in_out {
            value(c)
        } else {
            capacity(g, a).to_string()
        };
        writeln!(
            w,
            "\tif ({} > {max}) {{\n\t\t{} = {};",
            body_field(c, false),
            value(c),
            body_field(c, false)
        )?;
        return_error(w, g, rt, "MIG_ARRAY_TOO_LARGE")?;
        writeln!(w, "\t}}")?;
    }
    Ok(())
}

fn extract_body(w: &mut dyn Write, g: &Gen, rt: &Routine, a: &Arg) -> io::Result<()> {
    let t = &g.types[a.ty];
    let dst = value(a);
    let src = if a.has(ak::USER_IMPLICIT) {
        format!("TrailerP->{}", a.msg_field())
    } else {
        body_field(a, false)
    };
    if t.is_string {
        writeln!(w, "\t(void)mig_strncpy({dst}, {src}, {});", t.number)?;
    } else if t.is_variable_sized_untyped() {
        let c = &rt[a.count.expect("array count")];
        let count = body_field(c, false);
        let max = if a.count_in_out {
            value(c)
        } else {
            capacity(g, a).to_string()
        };
        let bytes = g.types[t.element.expect("array element")].type_size;
        writeln!(w, "\tif ({count} > {max}) {{\n\t\tmemcpy({dst}, {src}, {max} * {bytes});\n\t\t{} = {count};", value(c))?;
        return_error(w, g, rt, "MIG_ARRAY_TOO_LARGE")?;
        writeln!(w, "\t}}\n\tmemcpy({dst}, {src}, {count} * {bytes});")?;
    } else if t.is_optional_native() {
        writeln!(
            w,
            "\tif (Out{}P->__Present__{}) {{",
            a.reply_pos,
            a.msg_field()
        )?;
        utils::write_copy_type(
            w,
            t,
            false,
            &dst,
            &format!("{src}.__Real__{}", a.msg_field()),
        )?;
        writeln!(
            w,
            "\t}} else {{\n\t\t{dst} = {};\n\t}}",
            t.bad_value.as_deref().expect("optional bad value")
        )?;
    } else {
        utils::write_copy_type(w, t, false, &dst, &src)?;
    }
    Ok(())
}

fn write_routine(w: &mut dyn Write, g: &Gen, rt: &Routine) -> io::Result<()> {
    if !rt.one_way {
        write_checker(w, g, rt)?;
    }
    writeln!(w, "\n/* {} {} */", rt.kind_str(), rt.name)?;
    utils::write_mig_external(w)?;
    writeln!(w, "{} {}\n(", utils::return_type_str(g, rt), rt.user_name)?;
    utils::write_list(w, rt, ak::USER_ARG, ",\n", "\n", |w, a| {
        utils::write_user_var_decl(w, g, rt, a)
    })?;
    writeln!(w, ")\n{{")?;
    utils::write_struct_decl(
        w,
        g,
        rt,
        Spelling::User,
        ak::REQUEST,
        "Request",
        rt.simple_request,
        false,
        false,
        false,
    )?;
    if !rt.one_way {
        writeln!(w, "\ttypedef {} __Reply;", reply_type(rt))?;
        utils::write_struct_decl(
            w,
            g,
            rt,
            Spelling::User,
            ak::REPLY,
            "Reply",
            rt.simple_reply,
            true,
            rt.user_impl != 0,
            false,
        )?;
    }
    if rt.overwrite != 0 && g.opts.use_msg_rpc {
        // Scatter descriptors remain separate from the request and share only
        // the receive buffer with the reply.
        writeln!(
            w,
            "\ttypedef struct {{\n\t\tmach_msg_header_t Head;\n\t\tmach_msg_body_t msgh_body;"
        )?;
        for a in rt.iter().filter(|a| a.has(ak::OVERWRITE)) {
            utils::write_field_decl_prim(w, g, rt, a, Spelling::Kpd)?;
            writeln!(w)?;
        }
        writeln!(
            w,
            "\t\tmach_msg_trailer_t trailer;\n\t}} OverwriteTemplate;"
        )?;
        writeln!(w, "\tstruct {}MessS {{\n\t\tRequest In;\n\t\tunion {{ Reply Out; OverwriteTemplate In; }} Receive;\n\t}}", rt.name)?;
        let access = if rt.mess_on_stack() {
            writeln!(w, "\tMess;")?;
            "."
        } else {
            writeln!(
                w,
                "\t*Mess = (struct {}MessS *)mig_user_allocate(sizeof(*Mess));",
                rt.name
            )?;
            "->"
        };
        writeln!(w, "\tRequest *In0P = &Mess{access}In;\n\tReply *Out0P = &Mess{access}Receive.Out;\n\tOverwriteTemplate *InOvTemplate = &Mess{access}Receive.In;")?;
    } else {
        writeln!(w, "\tunion {}MessU {{\n\t\tRequest In;", rt.name)?;
        if !rt.one_way {
            writeln!(w, "\t\tReply Out;")?;
        }
        if rt.mess_on_stack() {
            writeln!(w, "\t}} Mess;\n\tRequest *In0P = &Mess.In;")?;
            if !rt.one_way {
                writeln!(w, "\tReply *Out0P = &Mess.Out;")?;
            }
        } else {
            writeln!(w, "\t}} *Mess = (union {}MessU *)mig_user_allocate(sizeof(*Mess));\n\tRequest *In0P = &Mess->In;", rt.name)?;
            if !rt.one_way {
                writeln!(w, "\tReply *Out0P = &Mess->Out;")?;
            }
        }
    }
    for pos in 1..=rt.max_request_pos {
        writeln!(w, "\tRequest *In{pos}P;")?;
    }
    if !rt.one_way {
        for pos in 1..=rt.max_reply_pos {
            writeln!(w, "\tReply *Out{pos}P;")?;
        }
    }
    writeln!(
        w,
        "\tmach_msg_return_t msg_result;\n\tmach_msg_size_t msgh_size = {};",
        minimum(g, rt, ak::REQUEST, "Request")
    )?;
    if rt.num_request_var != 0 {
        writeln!(w, "\tmach_msg_size_t msgh_size_delta;")?;
    }
    if !rt.one_way {
        writeln!(w, "\tmach_port_t reply_port;")?;
    }
    utils::write_appl_macro(w, g, "Send", "Declare", rt)?;
    if let Some(c) = rt.retc_arg.filter(|_| !rt.simple_request) {
        writeln!(w, "\tif ({}) {{\n\t\t((mig_reply_error_t *)In0P)->RetCode = {};\n\t\t((mig_reply_error_t *)In0P)->NDR = NDR_record;\n\t\tmsgh_size = sizeof(mig_reply_error_t);\n\t\tgoto ready_to_send;\n\t}}", value(&rt[c]), value(&rt[c]))?;
    }
    if !rt.simple_request {
        writeln!(
            w,
            "\tIn0P->msgh_body.msgh_descriptor_count = {};",
            rt.request_kpds
        )?;
    }
    for a in rt.iter().filter(|a| a.has_all(ak::SEND_SND | ak::SEND_KPD)) {
        pack_descriptor(w, g, rt, a)?;
    }
    let mut pending: Option<&Arg> = None;
    for a in rt.iter() {
        if let Some(last) = pending {
            if a.has(ak::SEND_BODY) && last.request_pos < a.request_pos {
                writeln!(w, "\tmsgh_size_delta = {};\n\tmsgh_size += msgh_size_delta;\n\tIn{}P = (Request *)((char *)In{}P + msgh_size_delta - {});", variable_size(g, rt, last, true), last.request_pos + 1, last.request_pos, variable_max(g, last))?;
                pending = None;
            }
        }
        if a.has_all(ak::SEND_SND | ak::SEND_BODY) {
            // Inline-array counts are emitted with their parent before copying
            // the data; skip their later linked-list entry.
            if !(a.ident() == ak::E_COUNT
                && a.parent
                    .map(|p| g.types[rt[p].ty].is_variable_sized_untyped())
                    .unwrap_or(false))
            {
                pack_body(w, g, rt, a)?;
            }
            if a.has(ak::VARIABLE) {
                pending = Some(a);
            }
        }
    }
    if let Some(last) = pending {
        writeln!(w, "\tmsgh_size += {};", variable_size(g, rt, last, true))?;
    }
    if rt.retc_arg.is_some() && !rt.simple_request {
        writeln!(w, "ready_to_send:")?;
    }
    let complex = if rt.simple_request {
        String::new()
    } else if let Some(c) = rt.retc_arg {
        format!("({} ? 0 : MACH_MSGH_BITS_COMPLEX) | ", value(&rt[c]))
    } else {
        "MACH_MSGH_BITS_COMPLEX | ".to_string()
    };
    writeln!(
        w,
        "\tIn0P->Head.msgh_bits = {complex}MACH_MSGH_BITS({}, {});",
        disposition(rt, g, rt.request_port()),
        disposition(rt, g, rt.reply_port())
    )?;
    writeln!(
        w,
        "\tIn0P->Head.msgh_remote_port = (mach_port_t){};",
        value(rt.request_port())
    )?;
    let reply = if rt.reply_port().has(ak::USER_ARG) {
        format!("(mach_port_t){}", value(rt.reply_port()))
    } else if rt.one_way {
        "MACH_PORT_NULL".to_string()
    } else if rt.use_special_reply_port {
        "mig_get_special_reply_port()".to_string()
    } else {
        "mig_get_reply_port()".to_string()
    };
    if rt.one_way {
        writeln!(w, "\tIn0P->Head.msgh_local_port = {reply};")?;
    } else {
        writeln!(w, "\treply_port = In0P->Head.msgh_local_port = {reply};")?;
    }
    writeln!(w, "\tIn0P->Head.msgh_size = msgh_size;\n\tIn0P->Head.msgh_id = {};\n\tIn0P->Head.msgh_reserved = 0;", g.opts.subsystem_base + rt.number)?;
    if g.opts.is_voucher_code_allowed && !g.opts.is_kernel_user && !g.opts.is_kernel_server {
        writeln!(w, "#ifdef USING_VOUCHERS\n\tif (voucher_mach_msg_set != NULL)\n\t\tvoucher_mach_msg_set(&In0P->Head);\n#endif")?;
    }
    utils::write_appl_macro(w, g, "Send", "Before", rt)?;
    write_transport(w, g, rt)?;
    if !rt.one_way {
        write!(
            w,
            "\tmsg_result = __MIG_check__Reply__{}_t(({} *)Out0P",
            rt.name,
            reply_type(rt)
        )?;
        for pos in 1..=rt.max_reply_pos {
            write!(w, ", ({} **)&Out{pos}P", reply_type(rt))?;
        }
        writeln!(w, ");\n\tif (msg_result != MACH_MSG_SUCCESS) {{")?;
        destroy(w, g, "Out0P")?;
        return_error(w, g, rt, "msg_result")?;
        writeln!(w, "\t}}")?;
        if rt.user_impl != 0 {
            writeln!(w, "\tmach_msg_max_trailer_t *TrailerP = (mach_msg_max_trailer_t *)((char *)Out0P + _WALIGN_(Out0P->Head.msgh_size));\n\tif (TrailerP->msgh_trailer_type != MACH_MSG_TRAILER_FORMAT_0)")?;
            return_error(w, g, rt, "MIG_TRAILER_ERROR")?;
            for a in rt.iter().filter(|a| a.has(ak::USER_IMPLICIT)) {
                writeln!(w, "#if __MigTypeCheck\n\tif (TrailerP->msgh_trailer_size < __builtin_offsetof(mach_msg_max_trailer_t, {}) + sizeof(TrailerP->{}))", a.msg_field(), a.msg_field())?;
                return_error(w, g, rt, "MIG_TRAILER_ERROR")?;
                writeln!(w, "#endif")?;
            }
        }
        for a in rt.iter() {
            if a.has_all(ak::RETURN_RCV | ak::RETURN_KPD) {
                extract_descriptor(w, g, rt, a)?;
            } else if a.has_all(ak::RETURN_RCV | ak::RETURN_BODY) || a.has(ak::USER_IMPLICIT) {
                extract_body(w, g, rt, a)?;
            }
        }
    }
    if !rt.mess_on_stack() {
        writeln!(
            w,
            "\tmig_user_deallocate((char *)Mess, (mach_msg_size_t)sizeof(*Mess));"
        )?;
    }
    writeln!(
        w,
        "\treturn {};\n}}",
        if rt.one_way {
            "msg_result"
        } else {
            "KERN_SUCCESS"
        }
    )
}
