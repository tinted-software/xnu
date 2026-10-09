// SPDX-License-Identifier: MIT
// Server-side marshaling follows migcom.tproj/server.c and the checked
// argument list in routine.rs. KernelServer's kdata and udata are deliberately
// never treated as adjacent: ipc_kobject may allocate them separately.

use std::io::{self, Write};

use super::header;
use super::utils::*;
use super::Gen;
use crate::routine::{ak, count_arg_descriptors, Arg, Dealloc, Kpd, Routine};
use crate::types::{fl, ipc_type_num::*, IpcType};

pub fn write_server(w: &mut dyn Write, g: &Gen) -> io::Result<()> {
    write_identification(w, g.opts)?;
    write_bogus_defines(w)?;
    write_includes(w, g, false, false)?;
    writeln!(w, "#include <mach/mig.h>")?;
    write_impl_imports(w, g.stmts, false)?;
    if let Some(path) = g
        .opts
        .server_header_filename
        .as_deref()
        .filter(|p| *p != "/dev/null")
    {
        writeln!(w, "#include \"{}\"", base_name(path))?;
    }
    if g.opts.is_kernel_server {
        writeln!(w, "#if __MigKernelSpecificCode")?;
        writeln!(w, "#define msgh_request_port msgh_remote_port")?;
        writeln!(w, "#define msgh_reply_port msgh_local_port")?;
        writeln!(
            w,
            "#define MACH_MSGH_BITS_REQUEST(bits) MACH_MSGH_BITS_REMOTE(bits)"
        )?;
        writeln!(
            w,
            "#define MACH_MSGH_BITS_REPLY(bits) MACH_MSGH_BITS_LOCAL(bits)"
        )?;
        writeln!(w, "#else")?;
    }
    writeln!(w, "#define msgh_request_port msgh_local_port")?;
    writeln!(w, "#define msgh_reply_port msgh_remote_port")?;
    writeln!(
        w,
        "#define MACH_MSGH_BITS_REQUEST(bits) MACH_MSGH_BITS_LOCAL(bits)"
    )?;
    writeln!(
        w,
        "#define MACH_MSGH_BITS_REPLY(bits) MACH_MSGH_BITS_REMOTE(bits)"
    )?;
    if g.opts.is_kernel_server {
        writeln!(w, "#endif /* __MigKernelSpecificCode */")?;
    }
    // Error replies remain contiguous and simple even for split messages.
    writeln!(w, "#define MIG_RETURN_ERROR(X, code) do {{ \\")?;
    writeln!(w, "    ((mig_reply_error_t *)(X))->RetCode = (code); \\")?;
    writeln!(w, "    ((mig_reply_error_t *)(X))->NDR = NDR_record; \\")?;
    writeln!(w, "    (X)->Head.msgh_bits &= ~MACH_MSGH_BITS_COMPLEX; \\")?;
    writeln!(
        w,
        "    (X)->Head.msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t); \\"
    )?;
    writeln!(w, "    return; \\")?;
    writeln!(w, "}} while (0)")?;
    write_appl_defaults(w, "Rcv")?;
    if let Some(rcs) = g.opts.rcs_id.as_deref() {
        write_rcs_decl(w, &format!("{}_server", g.subsystem()), rcs)?;
    }
    write_request_types(w, g)?;
    write_reply_types(w, g)?;
    header::write_server_reply_union(w, g)?;
    for rt in g.routines {
        if g.opts
            .server_header_filename
            .as_deref()
            .filter(|p| *p != "/dev/null")
            .is_none()
        {
            header::write_server_routine(w, g, rt)?;
        }
        write_check_request(w, g, rt)?;
        write_routine(w, g, rt)?;
    }
    write_dispatcher(w, g)
}

fn in_head(g: &Gen) -> &'static str {
    if g.opts.use_mach_msg2 {
        "InKP"
    } else {
        "In0P"
    }
}

fn out_head(g: &Gen) -> &'static str {
    if g.opts.use_mach_msg2 {
        "OutKP"
    } else {
        "OutP"
    }
}

fn in_ptr(g: &Gen, pos: u32) -> String {
    if g.opts.use_mach_msg2 {
        format!("In{pos}UP")
    } else {
        format!("In{pos}P")
    }
}

fn out_ptr(g: &Gen) -> &'static str {
    if g.opts.use_mach_msg2 {
        "OutUP"
    } else {
        "OutP"
    }
}

fn raw_in(g: &Gen, a: &Arg) -> String {
    let ptr = if a.has(ak::SERVER_IMPLICIT) {
        "TrailerP".to_string()
    } else if matches!(a.ident(), ak::E_REQUEST_PORT | ak::E_REPLY_PORT) || a.has(ak::SEND_KPD) {
        in_head(g).to_string()
    } else if a.ident() == ak::E_POLY && a.suffix.is_some() {
        in_head(g).to_string()
    } else {
        in_ptr(g, a.request_pos)
    };
    format!("{ptr}->{}", a.suffix_or_field())
}

fn raw_out(g: &Gen, a: &Arg) -> String {
    let ptr = if a.has(ak::RETURN_KPD) || (a.ident() == ak::E_POLY && a.suffix.is_some()) {
        out_head(g)
    } else {
        out_ptr(g)
    };
    format!("{ptr}->{}", a.suffix_or_field())
}

fn local(a: &Arg, it: &IpcType) -> bool {
    a.has(ak::VAR_NEEDED) || (it.is_optional_native() && a.has(ak::RETURN_SND))
}

fn count_in(g: &Gen, rt: &Routine, a: &Arg) -> String {
    if let Some(p) = a.parent {
        let parent = &rt[p];
        let it = &g.types[parent.ty];
        if !it.is_multiple_kpd() && !a.by_reference_server {
            let desc = format!("{}->{}", in_head(g), parent.msg_field());
            match parent.kpd {
                Some(Kpd::OolPorts) => return format!("{desc}.count"),
                Some(Kpd::Ool) => {
                    let bytes = a.multiplier * it.size / 8;
                    return if bytes > 1 {
                        format!("({desc}.size / {bytes})")
                    } else {
                        format!("{desc}.size")
                    };
                }
                _ => {}
            }
        }
    }
    raw_in(g, a)
}

fn input_value(g: &Gen, rt: &Routine, a: &Arg) -> String {
    let it = &g.types[a.ty];
    let mut value = if a.flags & fl::RET_CODE != 0 {
        "KERN_SUCCESS".to_string()
    } else if a.ident() == ak::E_COUNT {
        count_in(g, rt, a)
    } else if it.is_optional_native() {
        let ptr = in_ptr(g, a.request_pos);
        let f = a.msg_field();
        return format!(
            "({ptr}->__Present__{f} ? &{ptr}->{f}.__Real__{f} : {})",
            it.bad_value.as_deref().unwrap()
        );
    } else {
        raw_in(g, a)
    };
    if g.opts.is_kernel_server && matches!(a.ident(), ak::E_REQUEST_PORT | ak::E_REPLY_PORT) {
        value = format!("(ipc_port_t)({value})");
    }
    if let Some(trans) = it.in_trans.as_deref() {
        value = format!("{trans}({value})");
    } else if a.has(ak::SEND_KPD) && !it.is_multiple_kpd() {
        value = format!("({})({value})", it.trans_type());
    }
    value
}

fn server_arg(g: &Gen, rt: &Routine, a: &Arg) -> String {
    let it = &g.types[a.ty];
    let byref = a.by_reference_server || it.native_pointer;
    if local(a, it) {
        return format!("{}{}", if byref { "&" } else { "" }, a.var_name());
    }
    if a.has(ak::SEND_RCV) {
        let value = input_value(g, rt, a);
        if it.is_optional_native() {
            return value;
        }
        if byref {
            // Only untranslated fields are used by reference. Translations
            // with InOut semantics have already been assigned a local.
            return format!("&({value})");
        }
        return value;
    }
    let value = raw_out(g, a);
    format!("{}{value}", if byref { "&" } else { "" })
}

fn max_count(g: &Gen, a: &Arg) -> u32 {
    let it = &g.types[a.ty];
    if it.is_multiple_kpd() {
        it.kpd_number
    } else {
        it.element
            .map(|e| {
                if g.types[e].number != 0 {
                    it.number / g.types[e].number
                } else {
                    0
                }
            })
            .unwrap_or(it.number)
    }
}

fn variable_max(g: &Gen, a: &Arg) -> String {
    let it = &g.types[a.ty];
    if it.is_optional_native() {
        format!("_WALIGNSZ_({})", it.server_type())
    } else {
        (it.type_size + it.pad_size).to_string()
    }
}

fn variable_size(g: &Gen, rt: &Routine, a: &Arg, request: bool) -> String {
    let it = &g.types[a.ty];
    let ptr = if request {
        in_ptr(g, a.request_pos)
    } else {
        out_ptr(g).to_string()
    };
    if it.is_optional_native() {
        return format!(
            "({ptr}->__Present__{} ? _WALIGNSZ_({}) : 0)",
            a.msg_field(),
            it.server_type()
        );
    }
    let count = &rt[a.count.expect("variable array has a count")];
    let cnt = if request {
        raw_in(g, count)
    } else {
        // Same reason as in write_pack_body: the reply pointer may already be
        // shifted, so use the count's value.
        returned_value(g, count)
    };
    let bytes = g.types[it.element.unwrap()].type_size;
    if bytes % 4 == 0 {
        format!("({bytes} * {cnt})")
    } else {
        format!("_WALIGN_({bytes} * {cnt})")
    }
}

fn write_ndr_use(w: &mut dyn Write, g: &Gen, rt: &Routine, a: &Arg, rep: &str) -> io::Result<()> {
    if !g.opts.check_ndr || !rt.ndr_code().has(ak::REQUEST) {
        return Ok(());
    }
    let name = format!(
        "__NDR_convert__{rep}__Request__{}_t__{}",
        rt.name,
        a.msg_field()
    );
    let ndr = in_ptr(g, 0);
    let value = if a.kpd == Some(Kpd::Ool) {
        format!("({})({})", g.types[a.ty].server_type(), raw_in(g, a))
    } else {
        format!("&{}", raw_in(g, a))
    };
    let count = a
        .count
        .map(|c| format!(", {}", raw_in(g, &rt[c])))
        .unwrap_or_default();
    writeln!(w, "#if defined({name}__defined)")?;
    writeln!(w, "\tif ({ndr}->NDR.{rep} != NDR_record.{rep})")?;
    writeln!(w, "\t\t{name}({value}, {ndr}->NDR.{rep}{count});")?;
    writeln!(w, "#endif")
}

fn write_check_request(w: &mut dyn Write, g: &Gen, rt: &Routine) -> io::Result<()> {
    let name = &rt.name;
    let head = in_head(g);
    let min = min_size(g, rt, ak::REQUEST, "__Request");
    if g.opts.check_ndr {
        for a in rt.iter().filter(|a| a.has(ak::SEND_NDR)) {
            for rep in ["int_rep", "char_rep", "float_rep"] {
                if rep == "int_rep" || !matches!(a.ident(), ak::E_COUNT | ak::E_COUNT_IN_OUT) {
                    write_ndr_convert_decl(w, g, rt, a, rep, "Request")?;
                }
            }
        }
    }
    writeln!(w, "\n#ifndef __MIG_check__Request__{name}_t__defined")?;
    writeln!(w, "#define __MIG_check__Request__{name}_t__defined")?;
    write!(
        w,
        "mig_internal kern_return_t __MIG_check__Request__{name}_t("
    )?;
    if g.opts.use_mach_msg2 {
        write!(
            w,
            "__RequestKData__{name}_t *InKP, __RequestUData__{name}_t *In0UP"
        )?;
    } else {
        write!(w, "__Request__{name}_t *In0P")?;
    }
    for pos in 1..=rt.max_request_pos {
        let ptr = in_ptr(g, pos);
        let ty = if g.opts.use_mach_msg2 {
            "__RequestUData"
        } else {
            "__Request"
        };
        write!(w, ", {ty}__{name}_t **{ptr}P")?;
    }
    writeln!(w, ")\n{{")?;
    writeln!(w, "\ttypedef __Request__{name}_t __Request;")?;
    for pos in 1..=rt.max_request_pos {
        let ptr = in_ptr(g, pos);
        let ty = if g.opts.use_mach_msg2 {
            "__RequestUData"
        } else {
            "__Request"
        };
        writeln!(w, "\t{ty}__{name}_t *{ptr};")?;
    }
    if rt.num_request_var > 0 {
        writeln!(w, "\tmach_msg_size_t msgh_size = {head}->Head.msgh_size;")?;
        writeln!(w, "\tmach_msg_size_t msgh_size_delta;")?;
    }
    writeln!(w, "\t(void){head};")?;
    if g.opts.use_mach_msg2 {
        writeln!(w, "\t(void)In0UP;")?;
    }
    writeln!(w, "#if __MigTypeCheck")?;
    let complex = if rt.simple_request {
        format!("({head}->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX)")
    } else {
        format!("!({head}->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) || {head}->msgh_body.msgh_descriptor_count != {}", rt.request_kpds)
    };
    let size = if rt.num_request_var == 0 {
        format!("{head}->Head.msgh_size != sizeof(__Request)")
    } else {
        format!("msgh_size < {min} || msgh_size > sizeof(__Request)")
    };
    writeln!(w, "\tif ({complex} || {size}) return MIG_BAD_ARGUMENTS;")?;
    writeln!(w, "#endif")?;
    // Convert each count before using it to bound or shift an inline field.
    for a in rt.iter().filter(|a| a.has_all(ak::REQUEST | ak::SEND_BODY)) {
        if a.has(ak::VARIABLE) {
            let it = &g.types[a.ty];
            if let Some(c) = a.count {
                if a.same_count.is_none() {
                    write_ndr_use(w, g, rt, &rt[c], "int_rep")?;
                }
            }
            let size = variable_size(g, rt, a, true);
            if !it.is_optional_native() {
                let count = raw_in(g, &rt[a.count.unwrap()]);
                let max = max_count(g, a);
                writeln!(w, "#if __MigTypeCheck")?;
                writeln!(w, "\tif ({count} > {max}) return MIG_BAD_ARGUMENTS;")?;
                writeln!(w, "#endif")?;
            }
            writeln!(w, "\tmsgh_size_delta = {size};")?;
            writeln!(w, "#if __MigTypeCheck")?;
            writeln!(w, "\tif (msgh_size < {min} || msgh_size_delta > msgh_size - {min}) return MIG_BAD_ARGUMENTS;")?;
            writeln!(w, "#endif")?;
            writeln!(w, "\tmsgh_size -= msgh_size_delta;")?;
            if a.request_pos < rt.max_request_pos {
                let current = in_ptr(g, a.request_pos);
                let next = in_ptr(g, a.request_pos + 1);
                let ty = if g.opts.use_mach_msg2 {
                    "__RequestUData"
                } else {
                    "__Request"
                };
                writeln!(w, "\t*{next}P = {next} = ({ty}__{name}_t *)((char *){current} + msgh_size_delta - {});", variable_max(g, a))?;
            }
        }
    }
    if rt.num_request_var > 0 {
        writeln!(
            w,
            "#if __MigTypeCheck\n\tif (msgh_size != {min}) return MIG_BAD_ARGUMENTS;\n#endif"
        )?;
    }
    if g.opts.check_ndr {
        for a in rt.iter().filter(|a| a.has(ak::SEND_NDR)) {
            if matches!(a.ident(), ak::E_COUNT | ak::E_COUNT_IN_OUT) {
                if a.parent
                    .map(|p| g.types[rt[p].ty].is_variable_sized_untyped())
                    .unwrap_or(false)
                {
                    continue;
                }
            }
            for rep in ["int_rep", "char_rep", "float_rep"] {
                if rep == "int_rep" || !matches!(a.ident(), ak::E_COUNT | ak::E_COUNT_IN_OUT) {
                    write_ndr_use(w, g, rt, a, rep)?;
                }
            }
        }
    }
    for a in rt.iter().filter(|a| a.has(ak::SEND_KPD)) {
        write_check_descriptor(w, g, rt, a)?;
    }
    for a in rt.iter().filter(|a| a.has_all(ak::REQUEST | ak::SEND_BODY)) {
        let it = &g.types[a.ty];
        if it.is_string {
            let field = format!("{}->{}", in_ptr(g, a.request_pos), a.msg_field());
            let bound = if it.var_array {
                raw_in(g, &rt[a.count.unwrap()])
            } else {
                it.number.to_string()
            };
            writeln!(w, "#if __MigTypeCheck")?;
            writeln!(w, "\tif ({bound} == 0 || strnlen({field}, {bound}) == {bound}) return MIG_BAD_ARGUMENTS;")?;
            writeln!(w, "#endif")?;
        }
    }
    writeln!(w, "\treturn MACH_MSG_SUCCESS;\n}}\n#endif\n")
}

fn descriptor_kind(kpd: Kpd) -> &'static str {
    match kpd {
        Kpd::Port => "MACH_MSG_PORT_DESCRIPTOR",
        Kpd::Ool => "MACH_MSG_OOL_DESCRIPTOR",
        Kpd::OolPorts => "MACH_MSG_OOL_PORTS_DESCRIPTOR",
    }
}

fn write_check_descriptor(w: &mut dyn Write, g: &Gen, rt: &Routine, a: &Arg) -> io::Result<()> {
    let it = &g.types[a.ty];
    let kpd = a.kpd.unwrap();
    let multiple = it.is_multiple_kpd();
    let elt = if multiple {
        &g.types[it.element.unwrap()]
    } else {
        it
    };
    let desc = format!(
        "{}->{}{}",
        in_head(g),
        a.msg_field(),
        if multiple { "[i]" } else { "" }
    );
    writeln!(w, "#if __MigTypeCheck")?;
    if multiple {
        writeln!(
            w,
            "\tfor (unsigned int i = 0; i < {}; ++i) {{",
            it.kpd_number
        )?;
    }
    let mut conditions = vec![format!("{desc}.type != {}", descriptor_kind(kpd))];
    let fixed = !it.var_array && !elt.var_array;
    if kpd != Kpd::Ool && !(kpd == Kpd::Port && it.var_array) {
        if a.poly.is_none() {
            conditions.push(format!("{desc}.disposition != {}", elt.out_name_str()));
        } else if kpd == Kpd::Port {
            let dispositions: &[&str] = match elt.out_name {
                MACH_MSG_TYPE_MOVE_RECEIVE => &["MACH_MSG_TYPE_MOVE_RECEIVE"],
                MACH_MSG_TYPE_MOVE_SEND => &[
                    "MACH_MSG_TYPE_MOVE_SEND",
                    "MACH_MSG_TYPE_COPY_SEND",
                    "MACH_MSG_TYPE_MAKE_SEND",
                ],
                MACH_MSG_TYPE_MOVE_SEND_ONCE => &[
                    "MACH_MSG_TYPE_MOVE_SEND_ONCE",
                    "MACH_MSG_TYPE_MAKE_SEND_ONCE",
                ],
                _ => &[],
            };
            if !dispositions.is_empty() {
                conditions.push(format!(
                    "({})",
                    dispositions
                        .iter()
                        .map(|d| format!("{desc}.disposition != {d}"))
                        .collect::<Vec<_>>()
                        .join(" && ")
                ));
            }
        }
    }
    if kpd == Kpd::Ool || kpd == Kpd::OolPorts {
        let field = if kpd == Kpd::Ool { "size" } else { "count" };
        if fixed {
            let size = if kpd == Kpd::Ool {
                (elt.number * elt.size + 7) / 8
            } else {
                elt.number
            };
            conditions.push(format!("{desc}.{field} != {size}"));
        } else if let Some(cid) = if multiple { a.sub_count } else { a.count } {
            let count = &rt[cid];
            let count_expr = format!("{}{}", raw_in(g, count), if multiple { "[i]" } else { "" });
            let bytes = if kpd == Kpd::Ool {
                (count.multiplier * elt.size / 8).max(1)
            } else {
                1
            };
            conditions.push(format!("{desc}.{field} / {bytes} != {count_expr}"));
            if elt.ool_number != 0 {
                conditions.push(format!("{count_expr} > {}", elt.ool_number));
            }
        }
    }
    writeln!(
        w,
        "\tif ({}) return MIG_TYPE_ERROR;",
        conditions.join(" || ")
    )?;
    if multiple {
        writeln!(w, "\t}}")?;
    }
    if multiple && it.var_array {
        let count = raw_in(g, &rt[a.count.unwrap()]);
        writeln!(
            w,
            "\tif ({count} > {}) return MIG_BAD_ARGUMENTS;",
            it.kpd_number
        )?;
    }
    writeln!(w, "#endif")
}

fn write_local(w: &mut dyn Write, g: &Gen, a: &Arg) -> io::Result<()> {
    let it = &g.types[a.ty];
    if it.is_variable_sized_untyped() || it.no_opt_array {
        let elt = &g.types[it.element.unwrap()];
        writeln!(
            w,
            "\t{} {}[{}];",
            elt.trans_type(),
            a.var_name(),
            max_count(g, a)
        )
    } else if it.is_multiple_kpd() {
        let elt = &g.types[it.element.unwrap()];
        let spelling = if elt.trans_type().is_empty() {
            "void *"
        } else {
            elt.trans_type()
        };
        writeln!(w, "\t{spelling} {}[{}];", a.var_name(), it.kpd_number)
    } else {
        writeln!(w, "\t{} {};", it.trans_type(), a.var_name())
    }
}

fn write_trailer_check(w: &mut dyn Write, g: &Gen, rt: &Routine) -> io::Result<()> {
    if rt.server_impl == 0 {
        return Ok(());
    }
    let head = in_head(g);
    if g.opts.use_mach_msg2 {
        writeln!(w, "\tTrailerP = InTrailerP;")?;
    } else {
        writeln!(w, "\tTrailerP = (mach_msg_max_trailer_t *)((char *)In0P + round_msg(In0P->Head.msgh_size));")?;
    }
    writeln!(w, "\tif (TrailerP->msgh_trailer_type != MACH_MSG_TRAILER_FORMAT_0) {{ MIG_RETURN_ERROR({}, MIG_TRAILER_ERROR); }}", out_head(g))?;
    for a in rt.iter().filter(|a| a.has(ak::SERVER_IMPLICIT)) {
        let field = a.msg_field();
        let err_head = out_head(g);
        writeln!(w, "#if __MigTypeCheck")?;
        writeln!(w, "\tif (TrailerP->msgh_trailer_size < offsetof(mach_msg_max_trailer_t, {field}) + sizeof(TrailerP->{field})) {{ MIG_RETURN_ERROR({err_head}, MIG_TRAILER_ERROR); }}")?;
        writeln!(w, "#endif")?;
    }
    writeln!(w, "\t(void){head};")
}

fn write_routine(w: &mut dyn Write, g: &Gen, rt: &Routine) -> io::Result<()> {
    let name = &rt.name;
    let head = out_head(g);
    writeln!(w, "\nmig_internal void _X{name}(mach_msg_header_t *InHeadP,{} mach_msg_header_t *OutHeadP{})\n{{",
        if g.opts.use_mach_msg2 { " void *InDataP, mach_msg_max_trailer_t *InTrailerP," } else { "" },
        if g.opts.use_mach_msg2 { ", void *OutDataP" } else { "" })?;
    writeln!(w, "\ttypedef __Request__{name}_t Request;")?;
    writeln!(w, "\ttypedef __Reply__{name}_t Reply;")?;
    if g.opts.use_mach_msg2 {
        writeln!(w, "\ttypedef __RequestKData__{name}_t RequestK;\n\ttypedef __RequestUData__{name}_t RequestU;")?;
        writeln!(
            w,
            "\ttypedef __ReplyKData__{name}_t ReplyK;\n\ttypedef __ReplyUData__{name}_t ReplyU;"
        )?;
        writeln!(
            w,
            "\tRequestK *InKP = (RequestK *)InHeadP;\n\tRequestU *In0UP = (RequestU *)InDataP;"
        )?;
        writeln!(
            w,
            "\tReplyK *OutKP = (ReplyK *)OutHeadP;\n\tReplyU *OutUP = (ReplyU *)OutDataP;"
        )?;
        writeln!(w, "\t(void)In0UP; (void)OutUP; (void)InTrailerP;")?;
    } else {
        writeln!(
            w,
            "\tRequest *In0P = (Request *)InHeadP;\n\tReply *OutP = (Reply *)OutHeadP;"
        )?;
    }
    for pos in 1..=rt.max_request_pos {
        writeln!(
            w,
            "\t{} *{};",
            if g.opts.use_mach_msg2 {
                "RequestU"
            } else {
                "Request"
            },
            in_ptr(g, pos)
        )?;
    }
    writeln!(w, "\tkern_return_t RetCode;")?;
    if rt.server_impl != 0 {
        writeln!(w, "\tmach_msg_max_trailer_t *TrailerP;")?;
    }
    if rt.num_reply_var != 0 {
        writeln!(
            w,
            "\tmach_msg_size_t msgh_size = {};\n\tmach_msg_size_t msgh_size_delta;",
            min_size(g, rt, ak::REPLY, "Reply")
        )?;
    }
    for a in rt
        .iter()
        .filter(|a| a.has(ak::SERVER_ARG) && local(a, &g.types[a.ty]))
    {
        write_local(w, g, a)?;
    }
    write_appl_macro(w, g, "Rcv", "Declare", rt)?;
    write_appl_macro(w, g, "Rcv", "Before", rt)?;
    // RetCode one-way replies are allowed to arrive as a simple error even
    // when the successful notification carries descriptors.
    if rt.retc_arg.is_some() && !rt.simple_request {
        writeln!(w, "\tif (!(InHeadP->msgh_bits & MACH_MSGH_BITS_COMPLEX) && InHeadP->msgh_size == sizeof(mig_reply_error_t)) {{")?;
        write_trailer_check(w, g, rt)?;
        let args = rt
            .iter()
            .filter(|a| a.has(ak::SERVER_ARG))
            .map(|a| {
                if a.flags & fl::RET_CODE != 0 {
                    "((mig_reply_error_t *)InHeadP)->RetCode".to_string()
                } else if matches!(a.ident(), ak::E_REQUEST_PORT | ak::E_REPLY_PORT)
                    || a.has(ak::SERVER_IMPLICIT)
                {
                    input_value(g, rt, a)
                } else {
                    format!("({})0", g.types[a.ty].trans_type())
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(
            w,
            "\t\t(void){}({args});\n\t\tMIG_RETURN_ERROR({head}, MIG_NO_REPLY);\n\t}}",
            rt.server_name
        )?;
    }
    write!(w, "\tRetCode = __MIG_check__Request__{name}_t(")?;
    write!(
        w,
        "{}",
        if g.opts.use_mach_msg2 {
            "InKP, In0UP"
        } else {
            "In0P"
        }
    )?;
    for pos in 1..=rt.max_request_pos {
        write!(w, ", &{}", in_ptr(g, pos))?;
    }
    writeln!(
        w,
        ");\n\tif (RetCode != MACH_MSG_SUCCESS) {{ MIG_RETURN_ERROR({head}, RetCode); }}"
    )?;
    write_trailer_check(w, g, rt)?;
    for a in rt.iter().filter(|a| a.has(ak::RETURN_KPD)) {
        write_init_descriptor(w, g, rt, a)?;
    }
    for a in rt.iter().filter(|a| a.has(ak::SERVER_ARG)) {
        let it = &g.types[a.ty];
        if a.has(ak::SEND_RCV) && local(a, it) {
            if it.is_multiple_kpd() {
                let count = if it.var_array {
                    raw_in(g, &rt[a.count.unwrap()])
                } else {
                    it.kpd_number.to_string()
                };
                let member = if a.kpd == Some(Kpd::Port) {
                    "name"
                } else {
                    "address"
                };
                let elt = &g.types[it.element.unwrap()];
                writeln!(
                    w,
                    "\tfor (unsigned int i = 0; i < {count}; ++i) {}[i] = ({}){}->{}[i].{member};",
                    a.var_name(),
                    if elt.trans_type().is_empty() {
                        "void *"
                    } else {
                        elt.trans_type()
                    },
                    in_head(g),
                    a.msg_field()
                )?;
            } else {
                write_copy_type(w, it, false, a.var_name(), &input_value(g, rt, a))?;
            }
        }
        if a.ident() == ak::E_COUNT && a.has(ak::RETURN_SND) {
            let p = &rt[a.parent.unwrap()];
            let pt = &g.types[p.ty];
            if pt.is_variable_sized_untyped()
                || pt.mig_in_line
                || (pt.is_multiple_kpd() && pt.var_array)
            {
                let dest = if local(a, it) {
                    a.var_name().to_string()
                } else {
                    raw_out(g, a)
                };
                writeln!(w, "\t{dest} = {};", max_count(g, p))?;
                if let Some(c) = a.cinout {
                    let user = raw_in(g, &rt[c]);
                    writeln!(w, "\tif ({user} < {dest}) {dest} = {user};")?;
                }
            }
        }
    }
    let args = rt
        .iter()
        .filter(|a| a.has(ak::SERVER_ARG))
        .map(|a| server_arg(g, rt, a))
        .collect::<Vec<_>>()
        .join(", ");
    writeln!(w, "\tRetCode = {}({args});", rt.server_name)?;
    write_destroy_args(w, g, rt)?;
    writeln!(
        w,
        "\tif (RetCode != KERN_SUCCESS) {{ MIG_RETURN_ERROR({head}, RetCode); }}"
    )?;
    if g.opts.is_kernel_server {
        writeln!(w, "#if __MigKernelSpecificCode")?;
        for a in rt.iter().filter(|a| a.has(ak::SEND_KPD)) {
            let it = &g.types[a.ty];
            if it.in_trans.is_some() && it.out_name == MACH_MSG_TYPE_PORT_SEND {
                writeln!(
                    w,
                    "\tipc_port_release_send((ipc_port_t)({}));",
                    raw_in(g, a)
                )?;
            }
        }
        writeln!(w, "#endif")?;
    }
    if rt.one_way {
        write_appl_macro(w, g, "Rcv", "After", rt)?;
        writeln!(w, "\tMIG_RETURN_ERROR({head}, MIG_NO_REPLY);\n}}")?;
        return Ok(());
    }
    // KPD packing happens before shifting the pure-data pointer.
    for a in rt.iter().filter(|a| a.has(ak::RETURN_KPD)) {
        write_pack_descriptor(w, g, rt, a)?;
    }
    for a in rt.iter().filter(|a| a.has_all(ak::REPLY | ak::RETURN_BODY)) {
        write_pack_body(w, g, rt, a)?;
        if a.has(ak::VARIABLE) {
            writeln!(
                w,
                "\tmsgh_size_delta = {};\n\tmsgh_size += msgh_size_delta;",
                variable_size(g, rt, a, false)
            )?;
            if a.reply_pos < rt.max_reply_pos {
                writeln!(
                    w,
                    "\t{} = ({} *)((char *){} + msgh_size_delta - {});",
                    out_ptr(g),
                    if g.opts.use_mach_msg2 {
                        "ReplyU"
                    } else {
                        "Reply"
                    },
                    out_ptr(g),
                    variable_max(g, a)
                )?;
            }
        }
    }
    // The header pointer must not be the adjusted pointer used for packing.
    let original_head = if g.opts.use_mach_msg2 {
        "OutKP"
    } else {
        "((Reply *)OutHeadP)"
    };
    if !rt.simple_reply {
        writeln!(
            w,
            "\t{original_head}->Head.msgh_bits |= MACH_MSGH_BITS_COMPLEX;"
        )?;
        writeln!(
            w,
            "\t{original_head}->msgh_body.msgh_descriptor_count = {};",
            rt.reply_kpds
        )?;
    }
    let size = if rt.num_reply_var != 0 {
        "msgh_size".to_string()
    } else {
        min_size(g, rt, ak::REPLY, "Reply")
    };
    writeln!(w, "\t{original_head}->Head.msgh_size = {size};")?;
    write_appl_macro(w, g, "Rcv", "After", rt)?;
    writeln!(w, "}}")
}

fn write_init_descriptor(w: &mut dyn Write, g: &Gen, rt: &Routine, a: &Arg) -> io::Result<()> {
    let it = &g.types[a.ty];
    let multiple = it.is_multiple_kpd();
    let elt = if multiple {
        &g.types[it.element.unwrap()]
    } else {
        it
    };
    let desc = format!(
        "{}->{}{}",
        out_head(g),
        a.msg_field(),
        if multiple { "[i]" } else { "" }
    );
    if multiple {
        writeln!(
            w,
            "\tfor (unsigned int i = 0; i < {}; ++i) {{",
            it.kpd_number
        )?;
    }
    // Zero the descriptor including its ABI-specific padding. A compound
    // initializer is not usable here: in the kernel these structs carry
    // ptrauth-signed pointer members, so assignment is not a trivial copy.
    writeln!(w, "\t(void)memset(&{desc}, 0, sizeof({}));", it.kpd_type())?;
    writeln!(w, "\t{desc}.type = {};", descriptor_kind(a.kpd.unwrap()))?;
    if a.kpd != Some(Kpd::Ool) && a.poly.is_none() {
        if g.opts.is_kernel_server {
            writeln!(
                w,
                "#if __MigKernelSpecificCode\n\t{desc}.disposition = {};\n#else",
                elt.out_name_str()
            )?;
        }
        writeln!(w, "\t{desc}.disposition = {};", elt.in_name_str())?;
        if g.opts.is_kernel_server {
            writeln!(w, "#endif")?;
        }
    }
    if a.kpd != Some(Kpd::Port) {
        writeln!(
            w,
            "\t{desc}.copy = {};",
            if a.flags & fl::PHYSICAL_COPY != 0 {
                "MACH_MSG_PHYSICAL_COPY"
            } else {
                "MACH_MSG_VIRTUAL_COPY"
            }
        )?;
        if a.deallocate != Dealloc::Maybe {
            writeln!(
                w,
                "\t{desc}.deallocate = {};",
                if a.deallocate == Dealloc::Yes {
                    "TRUE"
                } else {
                    "FALSE"
                }
            )?;
        }
        if !elt.var_array {
            let (field, size) = if a.kpd == Some(Kpd::OolPorts) {
                ("count", elt.number)
            } else {
                ("size", (elt.number * elt.size + 7) / 8)
            };
            writeln!(w, "\t{desc}.{field} = {size};")?;
        }
    }
    if multiple {
        writeln!(w, "\t}}")?;
    }
    let _ = rt;
    Ok(())
}

fn returned_value(g: &Gen, a: &Arg) -> String {
    let it = &g.types[a.ty];
    if local(a, it) {
        a.var_name().to_string()
    } else if a.has(ak::REPLY_COPY) {
        raw_in(g, a)
    } else {
        raw_out(g, a)
    }
}

fn write_pack_descriptor(w: &mut dyn Write, g: &Gen, rt: &Routine, a: &Arg) -> io::Result<()> {
    let it = &g.types[a.ty];
    let multiple = it.is_multiple_kpd();
    let elt = if multiple {
        &g.types[it.element.unwrap()]
    } else {
        it
    };
    let desc = format!(
        "{}->{}{}",
        out_head(g),
        a.msg_field(),
        if multiple { "[i]" } else { "" }
    );
    if multiple {
        let count = if it.var_array {
            format!(
                "min({}, {})",
                it.kpd_number,
                returned_value(g, &rt[a.count.unwrap()])
            )
        } else {
            it.kpd_number.to_string()
        };
        writeln!(w, "\tfor (unsigned int i = 0; i < {count}; ++i) {{")?;
    }
    if local(a, it) || a.has(ak::REPLY_COPY) {
        let mut value = returned_value(g, a);
        if multiple {
            value.push_str("[i]");
        }
        if let Some(trans) = it.out_trans.as_deref() {
            value = format!("{trans}({value})");
        }
        let field = if a.kpd == Some(Kpd::Port) {
            "name"
        } else {
            "address"
        };
        let cast = if field == "name" {
            "mach_port_t"
        } else {
            "void *"
        };
        writeln!(w, "\t{desc}.{field} = ({cast})({value});")?;
    }
    if let Some(poly) = a.poly {
        writeln!(
            w,
            "\t{desc}.disposition = {};",
            returned_value(g, &rt[poly])
        )?;
    }
    if let Some(dealloc) = a.dealloc {
        writeln!(
            w,
            "\t{desc}.deallocate = {};",
            returned_value(g, &rt[dealloc])
        )?;
    }
    if a.kpd != Some(Kpd::Port) && elt.var_array {
        let count = &rt[if multiple {
            a.sub_count.unwrap()
        } else {
            a.count.unwrap()
        }];
        let value = format!(
            "{}{}",
            returned_value(g, count),
            if multiple { "[i]" } else { "" }
        );
        let (field, bytes) = if a.kpd == Some(Kpd::OolPorts) {
            ("count", 1)
        } else {
            ("size", (count.multiplier * elt.size / 8).max(1))
        };
        writeln!(w, "\t{desc}.{field} = {value} * {bytes};")?;
    }
    if multiple {
        writeln!(w, "\t}}")?;
    }
    if multiple && it.var_array && a.kpd != Some(Kpd::Port) && !elt.var_array {
        let cnt = returned_value(g, &rt[a.count.unwrap()]);
        writeln!(
            w,
            "\tfor (unsigned int i = min({}, {cnt}); i < {}; ++i) {desc}.{} = 0;",
            it.kpd_number,
            it.kpd_number,
            if a.kpd == Some(Kpd::OolPorts) {
                "count"
            } else {
                "size"
            }
        )?;
    }
    if g.opts.is_kernel_server
        && !multiple
        && a.kpd == Some(Kpd::Port)
        && matches!(
            it.out_name,
            MACH_MSG_TYPE_MOVE_RECEIVE | MACH_MSG_TYPE_POLYMORPHIC
        )
    {
        writeln!(w, "#if __MigKernelSpecificCode")?;
        let condition = if it.out_name == MACH_MSG_TYPE_POLYMORPHIC {
            format!("{desc}.disposition == MACH_MSG_TYPE_PORT_RECEIVE && ")
        } else {
            String::new()
        };
        let ih = in_head(g);
        let oh = out_head(g);
        writeln!(w, "\tif ({condition}IP_VALID((ipc_port_t){ih}->Head.msgh_reply_port) && IP_VALID((ipc_port_t){desc}.name) && ipc_port_check_circularity((ipc_port_t){desc}.name, (ipc_port_t){ih}->Head.msgh_reply_port)) {oh}->Head.msgh_bits |= MACH_MSGH_BITS_CIRCULAR;")?;
        writeln!(w, "#endif")?;
    }
    Ok(())
}

fn write_pack_body(w: &mut dyn Write, g: &Gen, rt: &Routine, a: &Arg) -> io::Result<()> {
    let it = &g.types[a.ty];
    let ptr = out_ptr(g);
    let field = format!("{ptr}->{}", a.msg_field());
    if a.ident() == ak::E_NDR_CODE {
        return writeln!(w, "\t{field} = NDR_record;");
    }
    if a.ident() == ak::E_RET_CODE {
        return writeln!(w, "\t{field} = RetCode;");
    }
    if it.is_variable_sized_untyped() {
        let count = &rt[a.count.unwrap()];
        let cntfield = format!("{ptr}->{}", count.msg_field());
        if it.is_string {
            if local(a, it) {
                writeln!(
                    w,
                    "\t{cntfield} = (mach_msg_type_number_t)mig_strncpy({field}, {}, {});",
                    a.var_name(),
                    it.number
                )?;
            } else {
                writeln!(
                    w,
                    "\t{cntfield} = (mach_msg_type_number_t)strnlen({field}, {}) + 1;",
                    it.number
                )?;
            }
            writeln!(w, "\t{ptr}->{}Offset = 0;", a.msg_field())?;
        } else {
            let value = returned_value(g, count);
            let bytes = g.types[it.element.unwrap()].type_size;
            // SameCount contributes no count field of its own.
            if a.flags & fl::SAME_COUNT == 0 && local(count, &g.types[count.ty]) {
                writeln!(w, "\t{cntfield} = {value};")?;
            }
            // Later arrays are packed through a pointer already shifted past
            // the earlier variable ones, so the count is read from its value
            // (the local the implementation filled in), never from the reply
            // field through that pointer.
            writeln!(
                w,
                "\tif ({value} > {}) {{ MIG_RETURN_ERROR({}, MIG_ARRAY_TOO_LARGE); }}",
                max_count(g, a),
                out_head(g)
            )?;
            if local(a, it) {
                writeln!(
                    w,
                    "\t(void)memcpy({field}, {}, {bytes} * {value});",
                    a.var_name()
                )?;
            }
        }
    } else if it.is_optional_native() {
        let value = returned_value(g, a);
        let bad = it.bad_value.as_deref().unwrap();
        let f = a.msg_field();
        writeln!(w, "\t{ptr}->__Present__{f} = ({value} != {bad});")?;
        writeln!(w, "\tif ({ptr}->__Present__{f}) {{")?;
        write_copy_type(
            w,
            it,
            true,
            &format!("{field}.__Real__{f}"),
            &format!("*{value}"),
        )?;
        writeln!(w, "\t}}")?;
    } else if local(a, it) {
        let value = it
            .out_trans
            .as_ref()
            .map(|t| format!("{t}({})", a.var_name()))
            .unwrap_or_else(|| a.var_name().to_string());
        write_copy_type(w, it, true, &field, &value)?;
    } else if a.has(ak::REPLY_COPY) {
        write_copy_type(w, it, true, &field, &raw_in(g, a))?;
    }
    if it.pad_size != 0 {
        writeln!(
            w,
            "\t(void)memset({ptr}->{}, 0, {});",
            a.pad_name, it.pad_size
        )?;
    }
    Ok(())
}

fn write_destroy_args(w: &mut dyn Write, g: &Gen, rt: &Routine) -> io::Result<()> {
    for a in rt
        .iter()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .filter(|a| a.has(ak::DESTROY))
    {
        let it = &g.types[a.ty];
        if let Some(destructor) = it.destructor.as_deref() {
            let value = if local(a, it) {
                a.var_name().to_string()
            } else {
                input_value(g, rt, a)
            };
            writeln!(w, "\t{destructor}({value});")?;
        } else if a.kpd == Some(Kpd::Ool) {
            let value = raw_in(g, a);
            let size = format!("{}->{}.size", in_head(g), a.msg_field());
            if g.opts.is_kernel_server {
                writeln!(w, "#if __MigKernelSpecificCode\n\tvm_map_copy_discard((vm_map_copy_t)({value}));\n#else")?;
            }
            writeln!(w, "\tmig_deallocate((vm_address_t)({value}), {size});")?;
            if g.opts.is_kernel_server {
                writeln!(w, "#endif")?;
            }
            writeln!(w, "\t{value} = (void *)0;\n\t{size} = 0;")?;
        }
    }
    Ok(())
}

fn write_dispatcher(w: &mut dyn Write, g: &Gen) -> io::Result<()> {
    let demux = g.server_demux();
    let sub = g.server_subsys();
    let base = g.opts.subsystem_base;
    let end = base + g.rt_number;
    let (kern, k) = if g.opts.use_mach_msg2 {
        ("kern_", "k")
    } else {
        ("", "")
    };
    writeln!(
        w,
        "\nmig_external mig_{kern}routine_t {demux}_routine(mach_msg_header_t *InHeadP);"
    )?;
    if g.opts
        .server_header_filename
        .as_deref()
        .filter(|p| *p != "/dev/null")
        .is_none()
    {
        writeln!(w, "const struct {sub} {{\n\tmig_{kern}server_routine_t {k}server;\n\tmach_msg_id_t start;\n\tmach_msg_id_t end;\n\tunsigned int maxsize;\n\tvm_address_t reserved;\n\tstruct {kern}routine_descriptor {k}routine[{}];\n}} {sub} = {{", g.rt_number)?;
    } else {
        writeln!(w, "const struct {sub} {sub} = {{")?;
    }
    writeln!(w, "\t{demux}_routine, {base}, {end}, (mach_msg_size_t)sizeof(union __ReplyUnion__{sub}), (vm_address_t)0,\n\t{{")?;
    let mut routines = g.routines.iter().peekable();
    for number in 0..g.rt_number {
        if let Some(rt) = routines.peek().filter(|r| r.number == number) {
            let (_, argc) = count_arg_descriptors(rt, g.types);
            let desc = if g.opts.use_mach_msg2 {
                rt.reply_kpds.to_string()
            } else {
                "(routine_arg_descriptor_t)0".to_string()
            };
            writeln!(w, "\t\t{{ (mig_impl_routine_t)0, (mig_stub_{kern}routine_t)_X{}, {argc}, 0, {desc}, (mach_msg_size_t)sizeof(__Reply__{}_t) }},", rt.name, rt.name)?;
            routines.next();
        } else {
            writeln!(w, "\t\t{{ 0, 0, 0, 0, 0, 0 }},")?;
        }
    }
    writeln!(w, "\t}}\n}};")?;
    writeln!(w, "\nmig_external mig_{kern}routine_t {demux}_routine(mach_msg_header_t *InHeadP)\n{{\n\tif (InHeadP->msgh_id < {base} || InHeadP->msgh_id >= {end}) return 0;\n\treturn {sub}.{k}routine[InHeadP->msgh_id - {base}].{k}stub_routine;\n}}")?;
    writeln!(w, "\nmig_external boolean_t {demux}(mach_msg_header_t *InHeadP,{} mach_msg_header_t *OutHeadP{})\n{{",
        if g.opts.use_mach_msg2 { " void *InDataP, mach_msg_max_trailer_t *InTrailerP," } else { "" },
        if g.opts.use_mach_msg2 { ", void *OutDataP" } else { "" })?;
    writeln!(w, "\tmig_{kern}routine_t routine;\n\tOutHeadP->msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REPLY(InHeadP->msgh_bits), 0);\n\tOutHeadP->msgh_remote_port = InHeadP->msgh_reply_port;\n\tOutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);\n\tOutHeadP->msgh_local_port = MACH_PORT_NULL;\n\tOutHeadP->msgh_reserved = 0;\n\tOutHeadP->msgh_id = InHeadP->msgh_id + 100;\n\troutine = {demux}_routine(InHeadP);\n\tif (routine == 0) {{\n\t\t((mig_reply_error_t *)OutHeadP)->NDR = NDR_record;\n\t\t((mig_reply_error_t *)OutHeadP)->RetCode = MIG_BAD_ID;\n\t\treturn FALSE;\n\t}}")?;
    writeln!(
        w,
        "\troutine(InHeadP,{} OutHeadP{});\n\treturn TRUE;\n}}",
        if g.opts.use_mach_msg2 {
            " InDataP, InTrailerP,"
        } else {
            ""
        },
        if g.opts.use_mach_msg2 {
            ", OutDataP"
        } else {
            ""
        }
    )?;
    if g.opts.gen_sym_tab {
        writeln!(w, "\nmig_symtab_t _{}SymTab[] = {{", g.subsystem())?;
        for rt in g.routines {
            writeln!(
                w,
                "\t{{ \"{}\", {}, (void (*)(void))_X{} }},",
                rt.name,
                base + rt.number,
                rt.name
            )?;
        }
        writeln!(
            w,
            "}};\nint _{}SymTabBase = {base};\nint _{}SymTabEnd = {end};",
            g.subsystem(),
            g.subsystem()
        )?;
    }
    Ok(())
}
