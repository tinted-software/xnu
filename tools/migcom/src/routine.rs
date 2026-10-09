// SPDX-License-Identifier: MIT
// Routine and argument model — a port of migcom.tproj/routine.c.
//
// `check_routine` turns a parsed routine into MIG's argument list: the
// implicit NDR/RetCode/count/poly/dealloc/reply-port/msg-option arguments
// are inserted, every argument gets its `ak*` kind bits (which message and
// which section it travels in, who packs and unpacks it), kernel-processed
// arguments become descriptors, and variable-sized inline data is assigned
// request/reply positions. Code generation only reads the result.
//
// Arguments live in an arena and are chained through `next`, exactly like
// the original linked list, so implicit arguments are inserted at the same
// places and every cross-reference (count, parent, poly, …) is an index.

use crate::ast::{self, Direction, RoutineKind};
use crate::global::Options;
use crate::types::{fl, ipc_type_num::*, TypeId, Types};

/// `arg_kind_t` bits (routine.h).
pub mod ak {
    pub const E_NONE: u32 = 0;
    pub const E_NORMAL: u32 = 1;
    pub const E_REQUEST_PORT: u32 = 2;
    pub const E_WAIT_TIME: u32 = 3;
    pub const E_REPLY_PORT: u32 = 4;
    pub const E_MSG_OPTION: u32 = 5;
    pub const E_MSG_SEQNO: u32 = 6;
    pub const E_RET_CODE: u32 = 7;
    pub const E_NDR_CODE: u32 = 8;
    pub const E_COUNT: u32 = 9;
    pub const E_POLY: u32 = 10;
    pub const E_DEALLOC: u32 = 11;
    pub const E_COUNT_IN_OUT: u32 = 12;
    pub const E_SAME_COUNT: u32 = 13;
    pub const E_SUB_COUNT: u32 = 14;
    pub const E_IMPLICIT: u32 = 15;
    pub const E_SEC_TOKEN: u32 = 16;
    pub const E_AUDIT_TOKEN: u32 = 17;
    pub const E_CONTEXT_TOKEN: u32 = 18;
    pub const E_SEND_TIME: u32 = 19;

    pub const E_BITS: u32 = 0x0000_003f;
    pub const REQUEST: u32 = 0x0000_0040;
    pub const REPLY: u32 = 0x0000_0080;
    pub const USER_ARG: u32 = 0x0000_0100;
    pub const SERVER_ARG: u32 = 0x0000_0200;
    pub const SEND: u32 = 0x0000_0400;
    pub const SEND_BODY: u32 = 0x0000_0800;
    pub const SEND_SND: u32 = 0x0000_1000;
    pub const SEND_RCV: u32 = 0x0000_2000;
    pub const RETURN: u32 = 0x0000_4000;
    pub const RETURN_BODY: u32 = 0x0000_8000;
    pub const RETURN_SND: u32 = 0x0001_0000;
    pub const RETURN_RCV: u32 = 0x0002_0000;
    pub const RETURN_NDR: u32 = 0x0004_0000;
    pub const REPLY_INIT: u32 = 0x0008_0000;
    pub const REPLY_COPY: u32 = 0x0020_0000;
    pub const VAR_NEEDED: u32 = 0x0040_0000;
    pub const DESTROY: u32 = 0x0080_0000;
    pub const VARIABLE: u32 = 0x0100_0000;
    pub const SEND_NDR: u32 = 0x0400_0000;
    pub const SEND_KPD: u32 = 0x0800_0000;
    pub const RETURN_KPD: u32 = 0x1000_0000;
    pub const USER_IMPLICIT: u32 = 0x2000_0000;
    pub const SERVER_IMPLICIT: u32 = 0x4000_0000;
    pub const OVERWRITE: u32 = 0x8000_0000;

    pub const SEND_BITS: u32 = SEND | SEND_BODY | SEND_SND | SEND_RCV;
    pub const RETURN_BITS: u32 = RETURN | RETURN_BODY | RETURN_SND | RETURN_RCV;

    pub const IN: u32 = E_NORMAL | USER_ARG | SERVER_ARG | REQUEST | SEND_BITS;
    pub const OUT: u32 = E_NORMAL | USER_ARG | SERVER_ARG | REPLY | RETURN_BITS;
    pub const INOUT: u32 =
        E_NORMAL | USER_ARG | SERVER_ARG | REQUEST | REPLY | SEND_BITS | RETURN_BITS | REPLY_COPY;
    pub const SERVER_IMPL: u32 = E_IMPLICIT | SERVER_ARG | SERVER_IMPLICIT | SEND | SEND_RCV;
    pub const USER_IMPL: u32 = E_IMPLICIT | USER_ARG | USER_IMPLICIT | RETURN | RETURN_RCV;
    pub const SERVER_SEC_TOKEN: u32 = E_SEC_TOKEN | SERVER_ARG | SERVER_IMPLICIT | SEND | SEND_RCV;
    pub const USER_SEC_TOKEN: u32 = E_SEC_TOKEN | USER_ARG | USER_IMPLICIT | RETURN | RETURN_RCV;
    pub const SEC_TOKEN: u32 = SERVER_SEC_TOKEN | USER_SEC_TOKEN;
    pub const SERVER_AUDIT_TOKEN: u32 =
        E_AUDIT_TOKEN | SERVER_ARG | SERVER_IMPLICIT | SEND | SEND_RCV;
    pub const USER_AUDIT_TOKEN: u32 =
        E_AUDIT_TOKEN | USER_ARG | USER_IMPLICIT | RETURN | RETURN_RCV;
    pub const AUDIT_TOKEN: u32 = SERVER_AUDIT_TOKEN | USER_AUDIT_TOKEN;
    pub const SERVER_CONTEXT_TOKEN: u32 =
        E_CONTEXT_TOKEN | SERVER_ARG | SERVER_IMPLICIT | SEND | SEND_RCV;
    pub const MSG_SEQNO: u32 = E_MSG_SEQNO | SERVER_ARG | SERVER_IMPLICIT | SEND | SEND_RCV;
    pub const REQUEST_PORT: u32 =
        E_REQUEST_PORT | USER_ARG | SERVER_ARG | SEND | SEND_SND | SEND_RCV;
    pub const WAIT_TIME: u32 = E_WAIT_TIME | USER_ARG;
    pub const SEND_TIME: u32 = E_SEND_TIME | USER_ARG;
    pub const MSG_OPTION: u32 = E_MSG_OPTION | USER_ARG;
    pub const REPLY_PORT: u32 = E_REPLY_PORT | USER_ARG | SERVER_ARG | SEND | SEND_SND | SEND_RCV;
    pub const UREPLY_PORT: u32 = E_REPLY_PORT | USER_ARG | SEND | SEND_SND | SEND_RCV;
    pub const SREPLY_PORT: u32 = E_REPLY_PORT | SERVER_ARG | SEND | SEND_SND | SEND_RCV;
    pub const RET_CODE: u32 = E_RET_CODE | REPLY | RETURN_BODY;
    pub const COUNT: u32 = E_COUNT | USER_ARG | SERVER_ARG;
    pub const POLY: u32 = E_POLY;
    pub const DEALLOC: u32 = E_DEALLOC | USER_ARG;
    pub const COUNT_IN_OUT: u32 = E_COUNT_IN_OUT | REQUEST | SEND_BITS;

    /// `akCheck`
    pub fn check(k: u32, bits: u32) -> bool {
        k & bits != 0
    }
    /// `akCheckAll`
    pub fn check_all(k: u32, bits: u32) -> bool {
        k & bits == bits
    }
    /// `akIdent`
    pub fn ident(k: u32) -> u32 {
        k & E_BITS
    }
}

/// `mach_msg_descriptor_type_t` of a kernel-processed argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kpd {
    Port,
    Ool,
    OolPorts,
}

/// `dealloc_t`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dealloc {
    No,
    Yes,
    Maybe,
}

pub type ArgId = usize;

/// `argument_t`
#[derive(Clone, Debug)]
pub struct Arg {
    pub name: String,
    pub next: Option<ArgId>,
    pub kind: u32,
    pub ty: TypeId,
    pub kpd: Option<Kpd>,
    var_name: Option<String>,
    msg_field: Option<String>,
    pub tt_name: String,
    pub pad_name: String,
    pub suffix: Option<String>,
    pub flags: u32,
    pub deallocate: Dealloc,
    pub count_in_out: bool,
    pub count: Option<ArgId>,
    pub sub_count: Option<ArgId>,
    pub cinout: Option<ArgId>,
    pub poly: Option<ArgId>,
    pub dealloc: Option<ArgId>,
    pub same_count: Option<ArgId>,
    pub parent: Option<ArgId>,
    pub multiplier: u32,
    pub request_pos: u32,
    pub reply_pos: u32,
    pub by_reference_user: bool,
    pub by_reference_server: bool,
    pub in_segment: String,
    pub out_segment: String,
}

impl Arg {
    /// `argAlloc()` with name, kind and type filled in.
    fn new(name: impl Into<String>, kind: u32, ty: TypeId) -> Self {
        Arg {
            name: name.into(),
            next: None,
            kind,
            ty,
            kpd: None,
            var_name: None,
            msg_field: None,
            tt_name: String::new(),
            pad_name: String::new(),
            suffix: None,
            flags: fl::NONE,
            deallocate: Dealloc::No,
            count_in_out: false,
            count: None,
            sub_count: None,
            cinout: None,
            poly: None,
            dealloc: None,
            same_count: None,
            parent: None,
            multiplier: 1,
            request_pos: 0,
            reply_pos: 0,
            by_reference_user: false,
            by_reference_server: false,
            in_segment: String::new(),
            out_segment: String::new(),
        }
    }

    /// `argVarName`
    pub fn var_name(&self) -> &str {
        self.var_name.as_deref().unwrap_or(&self.name)
    }

    /// `argMsgField`
    pub fn msg_field(&self) -> &str {
        self.msg_field.as_deref().unwrap_or(&self.name)
    }

    /// `argSuffix` if set, else `argMsgField`.
    pub fn suffix_or_field(&self) -> &str {
        self.suffix.as_deref().unwrap_or_else(|| self.msg_field())
    }

    pub fn has(&self, bits: u32) -> bool {
        ak::check(self.kind, bits)
    }

    pub fn has_all(&self, bits: u32) -> bool {
        ak::check_all(self.kind, bits)
    }

    pub fn ident(&self) -> u32 {
        ak::ident(self.kind)
    }
}

/// `routine_t`
#[derive(Clone, Debug)]
pub struct Routine {
    pub name: String,
    pub kind: RoutineKind,
    pub number: u32,
    pub user_name: String,
    pub server_name: String,
    pub error_name: String,
    pub one_way: bool,
    pub simple_request: bool,
    pub simple_reply: bool,
    pub use_special_reply_port: bool,
    pub consume_on_send_error: ast::ConsumeOnSendError,
    pub num_request_var: u32,
    pub num_reply_var: u32,
    pub max_request_pos: u32,
    pub max_reply_pos: u32,
    pub request_kpds: u32,
    pub reply_kpds: u32,
    pub overwrite: u32,
    pub overwrite_kpds: u32,
    pub no_reply_args: bool,
    pub request_fits: bool,
    pub reply_fits: bool,
    pub request_used_limit: bool,
    pub reply_used_limit: bool,
    pub request_size_known: u32,
    pub reply_size_known: u32,
    pub server_impl: u32,
    pub user_impl: u32,
    pub retc_arg: Option<ArgId>,
    pub request_port: Option<ArgId>,
    pub reply_port: Option<ArgId>,
    pub ret_code: ArgId,
    pub ndr_code: ArgId,
    pub wait_time: Option<ArgId>,
    pub msg_option: Option<ArgId>,
    pub args: Vec<Arg>,
    pub head: Option<ArgId>,
}

/// Iterator over a routine's argument list, in `argNext` order.
pub struct ArgIter<'a> {
    rt: &'a Routine,
    cur: Option<ArgId>,
}

impl<'a> Iterator for ArgIter<'a> {
    type Item = &'a Arg;
    fn next(&mut self) -> Option<&'a Arg> {
        let id = self.cur?;
        let a = &self.rt.args[id];
        self.cur = a.next;
        Some(a)
    }
}

impl std::ops::Index<ArgId> for Routine {
    type Output = Arg;
    fn index(&self, id: ArgId) -> &Arg {
        &self.args[id]
    }
}

impl std::ops::IndexMut<ArgId> for Routine {
    fn index_mut(&mut self, id: ArgId) -> &mut Arg {
        &mut self.args[id]
    }
}

impl Routine {
    pub fn iter(&self) -> ArgIter<'_> {
        ArgIter {
            rt: self,
            cur: self.head,
        }
    }

    /// Argument ids in list order.
    pub fn ids(&self) -> Vec<ArgId> {
        let mut v = Vec::new();
        let mut cur = self.head;
        while let Some(id) = cur {
            v.push(id);
            cur = self.args[id].next;
        }
        v
    }

    fn push(&mut self, a: Arg) -> ArgId {
        self.args.push(a);
        self.args.len() - 1
    }

    fn prepend(&mut self, mut a: Arg) -> ArgId {
        a.next = self.head;
        let id = self.push(a);
        self.head = Some(id);
        id
    }

    fn insert_after(&mut self, after: ArgId, mut a: Arg) -> ArgId {
        a.next = self.args[after].next;
        let id = self.push(a);
        self.args[after].next = Some(id);
        id
    }

    /// `rtCheckMask`
    pub fn check_mask(&self, mask: u32) -> bool {
        self.iter().any(|a| a.has_all(mask))
    }

    /// `rtCountKPDs`
    fn count_kpds(&self, types: &Types, mask: u32) -> u32 {
        self.iter()
            .filter(|a| a.has_all(mask))
            .map(|a| types[a.ty].kpd_number)
            .sum()
    }

    /// `rtCountMask`
    fn count_mask(&self, mask: u32) -> u32 {
        self.iter().filter(|a| a.has_all(mask)).count() as u32
    }

    /// `rtMessOnStack`
    pub fn mess_on_stack(&self) -> bool {
        self.request_fits && self.reply_fits
    }

    pub fn ret_code(&self) -> &Arg {
        &self.args[self.ret_code]
    }

    pub fn ndr_code(&self) -> &Arg {
        &self.args[self.ndr_code]
    }

    pub fn request_port(&self) -> &Arg {
        &self.args[self
            .request_port
            .expect("checked routine has a request port")]
    }

    pub fn reply_port(&self) -> &Arg {
        &self.args[self.reply_port.expect("checked routine has a reply port")]
    }

    pub fn msg_option(&self) -> &Arg {
        &self.args[self.msg_option.expect("checked routine has a msg option")]
    }

    pub fn wait_time(&self) -> Option<&Arg> {
        self.wait_time.map(|id| &self.args[id])
    }

    /// `rtRoutineKindToStr`
    pub fn kind_str(&self) -> &'static str {
        match self.kind {
            RoutineKind::Routine => "Routine",
            RoutineKind::SimpleRoutine => "SimpleRoutine",
        }
    }
}

/// `rtCountArgDescriptors`: (descriptor count, argument word count).
pub fn count_arg_descriptors(rt: &Routine, types: &Types) -> (u32, u32) {
    let mut count = 0;
    let mut argcount = 0;
    for a in rt.iter() {
        if !a.has(ak::SERVER_ARG) {
            continue;
        }
        let it = &types[a.ty];
        let port = a.kpd == Some(Kpd::Port);
        let port_array = a.kpd == Some(Kpd::OolPorts);
        let user_struct = it.is_struct && it.in_line;
        let string = it.is_string && it.in_line;
        let arg_is_out = a.ident() == ak::E_NORMAL && a.has(ak::REPLY);
        let out_struct = it.is_struct && arg_is_out && !it.var_array;
        let out_word = user_struct && it.size <= 32 && it.number == 1 && arg_is_out;
        let var_array = it.var_array && !port && !port_array;
        let fixed_array = (!it.var_array && !port && !port_array && it.number > 1 && !user_struct)
            || string
            || out_word
            || out_struct;
        if fixed_array || port || var_array || port_array {
            count += 1;
            argcount += 1;
        } else if it.is_struct && it.number != 0 && it.size >= 32 {
            argcount += it.number * (it.size / 32);
        } else {
            argcount += 1;
        }
    }
    (count, argcount)
}

/// Global option state in effect at a routine's declaration.
pub struct CheckEnv<'a> {
    pub opts: &'a Options,
    pub quiet: bool,
}

impl CheckEnv<'_> {
    fn warn(&self, msg: &str) {
        if !self.quiet {
            eprintln!("warning: {msg}");
        }
    }
}

fn direction_kind(d: Direction) -> u32 {
    match d {
        Direction::None => ak::E_NONE,
        Direction::In => ak::IN,
        Direction::Out => ak::OUT,
        Direction::InOut => ak::INOUT,
        Direction::RequestPort => ak::REQUEST_PORT,
        Direction::ReplyPort => ak::REPLY_PORT,
        Direction::SReplyPort => ak::SREPLY_PORT,
        Direction::UReplyPort => ak::UREPLY_PORT,
        Direction::WaitTime => ak::WAIT_TIME,
        Direction::SendTime => ak::SEND_TIME,
        Direction::MsgOption => ak::MSG_OPTION,
        Direction::SecToken => ak::SEC_TOKEN,
        Direction::ServerSecToken => ak::SERVER_SEC_TOKEN,
        Direction::UserSecToken => ak::USER_SEC_TOKEN,
        Direction::AuditToken => ak::AUDIT_TOKEN,
        Direction::ServerAuditToken => ak::SERVER_AUDIT_TOKEN,
        Direction::UserAuditToken => ak::USER_AUDIT_TOKEN,
        Direction::ServerContextToken => ak::SERVER_CONTEXT_TOKEN,
        Direction::MsgSeqno => ak::MSG_SEQNO,
        Direction::ServerImpl => ak::SERVER_IMPL,
        Direction::UserImpl => ak::USER_IMPL,
    }
}

/// `rtCheckRoutine`: build and check the MIG argument list of `src`.
pub fn check_routine(
    src: &ast::Routine,
    number: u32,
    types: &mut Types,
    env: &CheckEnv,
) -> Result<Routine, String> {
    let o = env.opts;
    let one_way = src.kind == RoutineKind::SimpleRoutine;
    let mut rt = Routine {
        name: src.name.clone(),
        kind: src.kind,
        number,
        user_name: format!("{}{}", o.user_prefix, src.name),
        server_name: format!("{}{}", o.server_prefix, src.name),
        error_name: o.error_proc.clone(),
        one_way,
        simple_request: false,
        simple_reply: false,
        use_special_reply_port: o.use_special_reply_port && !one_way,
        consume_on_send_error: o.consume_on_send_error,
        num_request_var: 0,
        num_reply_var: 0,
        max_request_pos: 0,
        max_reply_pos: 0,
        request_kpds: 0,
        reply_kpds: 0,
        overwrite: 0,
        overwrite_kpds: 0,
        no_reply_args: false,
        request_fits: false,
        reply_fits: false,
        request_used_limit: false,
        reply_used_limit: false,
        request_size_known: 0,
        reply_size_known: 0,
        server_impl: 0,
        user_impl: 0,
        retc_arg: None,
        request_port: None,
        reply_port: None,
        ret_code: 0,
        ndr_code: 0,
        wait_time: None,
        msg_option: None,
        args: Vec::new(),
        head: None,
    };

    // The parsed arguments, in order.
    let mut prev: Option<ArgId> = None;
    for a in &src.args {
        let mut arg = Arg::new(a.name.clone(), direction_kind(a.direction), a.ty);
        arg.flags = a.flags;
        let id = match prev {
            None => rt.prepend(arg),
            Some(p) => rt.insert_after(p, arg),
        };
        prev = Some(id);
    }

    // rtAddRetCode, rtAddNdrCode: NDR first, then RetCode.
    rt.ret_code = rt.prepend(Arg::new("RetCode", ak::RET_CODE, types.ret_code));
    rt.ndr_code = rt.prepend(Arg::new("NDR_record", ak::E_NDR_CODE, types.ndr_code));

    check_routine_args(&mut rt, types, env)?;

    if rt.reply_port.is_none() {
        let ty = if rt.one_way {
            types.zero_reply_port
        } else {
            types.real_reply_port
        };
        add_dummy_reply_port(&mut rt, types, ty);
    } else if rt.reply_port().has(ak::USER_ARG) {
        // An explicit user reply port can't be assumed to be the SRP.
        rt.use_special_reply_port = false;
    }
    if rt.msg_option.is_none() {
        let name = o
            .msg_option
            .clone()
            .unwrap_or_else(|| "MACH_MSG_OPTION_NONE".into());
        add_msg_option(&mut rt, types, name);
    }
    if rt.wait_time.is_none() {
        if let Some(w) = &o.wait_time {
            add_wait_time(&mut rt, types, w.clone(), ak::E_WAIT_TIME);
        } else if let Some(s) = &o.send_time {
            add_wait_time(&mut rt, types, s.clone(), ak::E_SEND_TIME);
        }
    }
    if rt.wait_time.is_some() && rt.consume_on_send_error == ast::ConsumeOnSendError::None {
        env.warn(&format!(
            "{} {} specifies a SendTime/WaitTime which may leak resources, adopt \"ConsumeOnSendError Timeout\"",
            rt.kind_str(),
            rt.name
        ));
    }

    // rtCheckArgTypes
    let Some(rp) = rt.request_port else {
        return Err(format!(
            "{} {} doesn't have a server port argument",
            rt.kind_str(),
            rt.name
        ));
    };
    types.check_request_port_type(&rt[rp].name, rt[rp].ty)?;
    if let Some(id) = rt.reply_port {
        types.check_reply_port_type(&rt[id].name, rt[id].ty)?;
    }
    if let Some(id) = rt.wait_time {
        types.check_int_type(&rt[id].name, rt[id].ty)?;
    }
    if let Some(id) = rt.msg_option {
        types.check_int_type(&rt[id].name, rt[id].ty)?;
    }

    if rt.one_way && rt.check_mask(ak::RETURN) {
        return Err(format!("{} {} has OUT argument", rt.kind_str(), rt.name));
    }

    rt.server_impl = rt.count_mask(ak::SERVER_IMPLICIT);
    rt.user_impl = rt.count_mask(ak::USER_IMPLICIT);
    rt.simple_request = check_simple(&rt, types, ak::REQUEST);
    rt.simple_reply = check_simple(&rt, types, ak::REPLY);
    rt.request_kpds = rt.count_kpds(types, ak::SEND_KPD);
    rt.reply_kpds = rt.count_kpds(types, ak::RETURN_KPD);

    rt.overwrite = rt.iter().filter(|a| a.flags & fl::OVERWRITE != 0).count() as u32;
    if rt.overwrite != 0 {
        check_overwrite(&mut rt, types);
        rt.overwrite_kpds = rt.count_kpds(types, ak::RETURN_KPD | ak::OVERWRITE);
        if o.is_kernel_user {
            return Err("Overwrite option(s) do not match with the KernelUser personality".into());
        }
    }

    let (f, u, k) = check_fit(&rt, types, env, ak::REQUEST);
    rt.request_fits = f;
    rt.request_used_limit = u;
    rt.request_size_known = k;
    let (f, u, k) = check_fit(&rt, types, env, ak::REPLY);
    rt.reply_fits = f;
    rt.reply_used_limit = u;
    rt.reply_size_known = k;

    check_variable(&mut rt);
    check_destroy(&mut rt, types);
    add_by_reference(&mut rt, types, env);
    suffix_ext_arg(&mut rt, types)?;
    add_same_count(&mut rt, types)?;
    process_ret_code(&mut rt);
    process_ndr_code(&mut rt, types);
    if rt.user_impl != 0 {
        process_msg_option(&mut rt);
    }
    if rt.use_special_reply_port {
        if o.is_kernel_user || o.is_kernel_server {
            return Err(
                "UseSpecialReplyPort option cannot be used with KernelUser / KernelServer".into(),
            );
        }
        let mo = rt.msg_option.expect("msg option");
        let v = format!("{}|__MigSpecialReplyPortMsgOption", rt[mo].var_name());
        rt[mo].var_name = Some(v);
    }
    rt.no_reply_args = !rt.check_mask(ak::RETURN_SND);
    add_arg_segment(&mut rt, types, o);
    Ok(rt)
}

/// `rtCheckRoutineArgs`
fn check_routine_args(rt: &mut Routine, types: &mut Types, env: &CheckEnv) -> Result<(), String> {
    let o = env.opts;
    let mut old_arg: Option<ArgId> = None;
    let mut cur = rt.head;
    while let Some(id) = cur {
        // rtDefaultArgKind
        if rt[id].kind == ak::E_NONE && rt.request_port.is_none() {
            rt[id].kind = ak::REQUEST_PORT;
        }
        if rt[id].kind == ak::E_NONE {
            rt[id].kind = ak::IN;
        }
        // rtCheckRoutineArg
        match rt[id].ident() {
            ak::E_REQUEST_PORT => {
                if let Some(old) = rt.request_port {
                    env.warn(&format!(
                        "multiple RequestPort args in {}; {} won't be used",
                        rt.name, rt[old].name
                    ));
                }
                rt.request_port = Some(id);
            }
            ak::E_REPLY_PORT => {
                if let Some(old) = rt.reply_port {
                    env.warn(&format!(
                        "multiple ReplyPort args in {}; {} won't be used",
                        rt.name, rt[old].name
                    ));
                }
                rt.reply_port = Some(id);
            }
            ak::E_WAIT_TIME => {
                rt.wait_time = Some(id);
            }
            ak::E_SEND_TIME => {
                let after_wait = rt
                    .wait_time
                    .map(|w| rt[w].ident() == ak::E_WAIT_TIME)
                    .unwrap_or(false);
                if !after_wait {
                    rt.wait_time = Some(id);
                }
            }
            ak::E_MSG_OPTION => {
                rt.msg_option = Some(id);
            }
            _ => {}
        }
        set_arg_defaults(rt, types, id);

        let it = rt[id].ty;
        let name = rt[id].var_name().to_string();
        let kind = rt[id].kind;
        let flags = process_dealloc_flag(rt, types, env, id, o);
        rt[id].flags = flags;
        // rtProcessCountInOutFlag
        if rt[id].flags & fl::COUNT_IN_OUT != 0 {
            if !ak::check(kind, ak::REPLY) {
                env.warn(&format!(
                    "{name}: CountInOut is ignored: argument must be Out"
                ));
                rt[id].flags &= !fl::COUNT_IN_OUT;
            } else if !types[it].var_array || !types[it].in_line {
                env.warn(&format!(
                    "{name}: CountInOut is ignored: argument isn't variable or in-line"
                ));
                rt[id].flags &= !fl::COUNT_IN_OUT;
            } else {
                rt[id].count_in_out = true;
            }
        }
        process_same_count_flag(rt, types, env, id, &mut old_arg);
        // rtProcessPhysicalCopyFlag
        if rt[id].flags & fl::PHYSICAL_COPY != 0 {
            if types[it].in_line {
                env.warn(&format!(
                    "{name}: PhysicalCopy is ignored, argument copied inline anyway"
                ));
                rt[id].flags &= !fl::PHYSICAL_COPY;
            }
            if types[it].port_type {
                env.warn(&format!(
                    "{name}: PhysicalCopy is ignored, it does not apply to ports and array of ports"
                ));
                rt[id].flags &= !fl::PHYSICAL_COPY;
            }
        }
        // rtProcessRetCodeFlag
        if rt[id].flags & fl::RET_CODE != 0 {
            let t = &types[it];
            if !t.in_line || !t.is_struct || t.size != 32 || t.number != 1 {
                env.warn(&format!(
                    "{name}: RetCode is ignored - the type doesn't match a MIG RetCode"
                ));
                rt[id].flags &= !fl::RET_CODE;
            } else if rt.kind != RoutineKind::SimpleRoutine {
                return Err(format!(
                    "{name}: RetCode is allowed only for SimpleRoutines"
                ));
            } else if rt.retc_arg.is_some() {
                env.warn(&format!(
                    "{name}: RetCode is ignored - only one argument can be flagged as RetCode"
                ));
                rt[id].flags &= !fl::RET_CODE;
            } else {
                rt.retc_arg = Some(id);
            }
        }
        // rtProcessOverwriteFlag
        if rt[id].flags & fl::OVERWRITE != 0 {
            let t = &types[it];
            if t.in_line
                || t.mig_in_line
                || !ak::check(kind, ak::RETURN)
                || ak::check(kind, ak::SEND)
            {
                env.warn(&format!(
                    "{name}: Overwrite is ignored - it must be Out AND Ool!"
                ));
                rt[id].flags &= !fl::OVERWRITE;
            }
        }
        augment_arg_kind(rt, types, id)?;

        // Implicit arguments are processed by later iterations; their
        // order is 'arg poly countinout count dealloc'.
        if rt[id].deallocate == Dealloc::Maybe {
            add_dealloc_arg(rt, types, id);
        }
        let t = &types[it];
        let elem_var = t.element.map(|e| types[e].var_array).unwrap_or(false);
        if t.var_array || (t.is_multiple_kpd() && elem_var) {
            add_count_arg(rt, types, id);
        }
        if rt[id].count_in_out {
            add_count_in_out_arg(rt, types, id);
        }
        if types[it].in_name == MACH_MSG_TYPE_POLYMORPHIC
            || types[it].out_name == MACH_MSG_TYPE_POLYMORPHIC
        {
            add_poly_arg(rt, types, id, o.is_kernel_server);
        }
        detect_kpd_arg(rt, types, id);

        cur = rt[id].next;
    }
    Ok(())
}

/// `rtSetArgDefaults`
fn set_arg_defaults(rt: &mut Routine, types: &mut Types, id: ArgId) {
    let a = &mut rt.args[id];
    if a.var_name.is_none() {
        a.var_name = Some(a.name.clone());
    }
    if a.msg_field.is_none() {
        a.msg_field = Some(
            match ak::ident(a.kind) {
                ak::E_REQUEST_PORT => "Head.msgh_request_port",
                ak::E_REPLY_PORT => "Head.msgh_reply_port",
                ak::E_NDR_CODE => "NDR",
                ak::E_SEC_TOKEN => "msgh_sender",
                ak::E_AUDIT_TOKEN => "msgh_audit",
                ak::E_CONTEXT_TOKEN => "msgh_context",
                ak::E_MSG_SEQNO => "msgh_seqno",
                _ => a.name.as_str(),
            }
            .to_string(),
        );
    }
    if a.tt_name.is_empty() {
        a.tt_name = format!("{}Template", a.name);
    }
    if a.pad_name.is_empty() {
        a.pad_name = format!("{}Pad", a.name);
    }
    // The poly args of the request and reply ports live in msgh_bits.
    let ty = a.ty;
    if let Some(rp) = rt.request_port {
        if rt.args[rp].poly == Some(id) {
            rt.args[id].msg_field = Some("Head.msgh_bits".into());
            types[ty].in_trans = Some("MACH_MSGH_BITS_REQUEST".into());
        }
    }
    if let Some(rp) = rt.reply_port {
        if rt.args[rp].poly == Some(id) {
            rt.args[id].msg_field = Some("Head.msgh_bits".into());
            types[ty].in_trans = Some("MACH_MSGH_BITS_REPLY".into());
        }
    }
}

/// `rtProcessDeallocFlag`
fn process_dealloc_flag(
    rt: &mut Routine,
    types: &Types,
    env: &CheckEnv,
    id: ArgId,
    o: &Options,
) -> u32 {
    let it = &types[rt[id].ty];
    let kind = rt[id].kind;
    let name = rt[id].var_name().to_string();
    let mut flags = rt[id].flags;
    if flags & fl::MAYBE_DEALLOC != 0 && flags & (fl::DEALLOC | fl::NOT_DEALLOC) != 0 {
        env.warn(&format!(
            "{name}: Dealloc and NotDealloc ignored with Dealloc[]"
        ));
        flags &= !(fl::DEALLOC | fl::NOT_DEALLOC);
    }
    if flags & (fl::DEALLOC | fl::NOT_DEALLOC) == (fl::DEALLOC | fl::NOT_DEALLOC) {
        env.warn(&format!("{name}: Dealloc and NotDealloc cancel out"));
        flags &= !(fl::DEALLOC | fl::NOT_DEALLOC);
    }
    if ((o.is_kernel_server && ak::check(kind, ak::RETURN))
        || (o.is_kernel_user && ak::check(kind, ak::SEND)))
        && flags & fl::DEALLOC != 0
    {
        rt[id].deallocate = Dealloc::Yes;
    } else if flags & (fl::MAYBE_DEALLOC | fl::DEALLOC) != 0 {
        if it.in_line && !it.port_type {
            env.warn(&format!(
                "{name}: Dealloc is ignored: it is meaningless  for that type of argument"
            ));
            flags &= !(fl::MAYBE_DEALLOC | fl::DEALLOC);
        } else {
            rt[id].deallocate = if flags & fl::MAYBE_DEALLOC != 0 {
                Dealloc::Maybe
            } else {
                Dealloc::Yes
            };
        }
    }
    flags
}

/// `rtProcessSameCountFlag`
fn process_same_count_flag(
    rt: &mut Routine,
    types: &Types,
    env: &CheckEnv,
    id: ArgId,
    old_arg: &mut Option<ArgId>,
) {
    let mut flags = rt[id].flags;
    if flags & fl::SAME_COUNT != 0 {
        let name = rt[id].var_name().to_string();
        if !types[rt[id].ty].var_array {
            env.warn(&format!(
                "{name}: SameCount is ignored - the argument is not variable"
            ));
            flags &= !fl::SAME_COUNT;
        }
        if let Some(mut old) = *old_arg {
            if let Some(p) = rt[old].parent {
                old = p;
            }
            if let Some(s) = rt[old].same_count {
                old = s;
            }
            if !types[rt[old].ty].var_array {
                env.warn(&format!(
                    "{name}: SameCount is ignored - adjacent argument is not variable"
                ));
                flags &= !fl::SAME_COUNT;
            }
            const MASK: u32 = ak::E_BITS
                | ak::SEND
                | ak::RETURN
                | ak::REQUEST
                | ak::REPLY
                | ak::USER_ARG
                | ak::SERVER_ARG;
            if rt[old].kind & MASK != rt[id].kind & MASK
                || rt[old].count_in_out != rt[id].count_in_out
            {
                env.warn(&format!(
                    "{name}: SameCount is ignored - inconsistencies with the adjacent argument"
                ));
                flags &= !fl::SAME_COUNT;
            }
            rt[id].same_count = Some(old);
        }
        rt[id].flags = flags;
    }
    *old_arg = Some(id);
}

/// `rtAugmentArgKind`
fn augment_arg_kind(rt: &mut Routine, types: &Types, id: ArgId) -> Result<(), String> {
    let it = &types[rt[id].ty];
    let a = &mut rt.args[id];
    if it.is_variable_sized_untyped() {
        if ak::check_all(a.kind, ak::REQUEST | ak::REPLY) {
            return Err(format!(
                "{}: Inline variable-sized arguments can't be InOut",
                a.name
            ));
        }
        a.kind |= ak::VARIABLE;
    }
    if it.is_optional_native() {
        a.kind |= ak::VARIABLE;
    }
    // Cases needing a local variable in the server stub: an out-translation
    // of a returned value; an in-translation of an InOut value; a
    // destructor applied to an in-translated value; arrays of KPDs; and
    // returned poly/dealloc values.
    let k = a.kind;
    if (it.out_trans.is_some() && ak::check(k, ak::RETURN_SND))
        || (it.in_trans.is_some() && ak::check_all(k, ak::SEND_RCV | ak::RETURN_SND))
        || (it.destructor.is_some()
            && ak::check(k, ak::SEND_RCV)
            && !ak::check(k, ak::RETURN_SND)
            && it.in_trans.is_some())
        || it.is_multiple_kpd()
        || (ak::ident(k) == ak::E_POLY && ak::check(k, ak::RETURN_SND))
        || (ak::ident(k) == ak::E_DEALLOC && ak::check(k, ak::RETURN_SND))
    {
        a.kind &= !ak::REPLY_COPY;
        a.kind |= ak::VAR_NEEDED;
    }
    Ok(())
}

/// `rtAddCountArg`
fn add_count_arg(rt: &mut Routine, types: &mut Types, id: ArgId) {
    let it = rt[id].ty;
    let t = types[it].clone();
    let elem_var = t.element.map(|e| types[e].var_array).unwrap_or(false);
    let mut count;
    if t.is_multiple_kpd() && elem_var {
        let cty = types.make_sub_count_type(t.kpd_number, t.var_array);
        count = Arg::new(format!("{}Subs", rt[id].name), ak::E_SUB_COUNT, cty);
    } else {
        let cty = types.make_count_type();
        count = Arg::new(format!("{}Cnt", rt[id].name), ak::E_COUNT, cty);
    }
    let master = rt[id].parent.unwrap_or(id);
    count.multiplier = if types[rt[master].ty].is_multiple_kpd() {
        1
    } else {
        t.element.map(|e| types[e].number).unwrap_or(1)
    };
    count.parent = Some(id);
    let kind = rt[id].kind;
    if t.is_string {
        // C strings get no Count argument on either side, but the count is
        // still in the message.
        count.kind |= if ak::check(kind, ak::SEND) {
            ak::SEND_RCV
        } else {
            ak::RETURN_RCV
        };
    } else {
        count.kind |= ak::USER_ARG | ak::SERVER_ARG | (kind & !ak::E_BITS);
        count.kind &= !(ak::VARIABLE | ak::VAR_NEEDED);
        // The count of an inline variable array is declared together with
        // (before) the array, not as a separate field.
        if t.is_variable_sized_untyped() {
            count.kind &= !(ak::REQUEST | ak::REPLY);
        }
    }
    let is_sub = ak::ident(count.kind) == ak::E_SUB_COUNT;
    let cid = rt.insert_after(id, count);
    if is_sub {
        rt[id].sub_count = Some(cid);
    } else {
        rt[id].count = Some(cid);
        if let Some(p) = rt[id].parent {
            rt[p].count = Some(cid);
        }
    }
}

/// `rtAddCountInOutArg`: the request-side twin of an out array's count.
fn add_count_in_out_arg(rt: &mut Routine, types: &mut Types, id: ArgId) {
    let cty = types.make_count_type();
    let mut count = Arg::new(format!("{}Cnt", rt[id].name), ak::COUNT_IN_OUT, cty);
    let ocount = rt[id].count.expect("CountInOut arg has a count");
    count.cinout = Some(ocount);
    let cid = rt.insert_after(id, count);
    rt[ocount].cinout = Some(cid);
}

/// `rtAddPolyArg`
fn add_poly_arg(rt: &mut Routine, types: &mut Types, id: ArgId, is_kernel_server: bool) {
    let it = &types[rt[id].ty];
    let (inn, outn) = (it.in_name, it.out_name);
    let pty = types.make_poly_type();
    let mut poly = Arg::new(format!("{}Poly", rt[id].name), ak::POLY, pty);
    poly.parent = Some(id);

    // KernelServer packs Out arguments with OutNames, so the OutName also
    // decides whether they are poly-in.
    let mut akbsend = ak::SEND;
    let mut akbreturn = ak::RETURN;
    if inn == MACH_MSG_TYPE_POLYMORPHIC {
        akbsend |= ak::USER_ARG | ak::SEND_SND;
        if !is_kernel_server {
            akbreturn |= ak::SERVER_ARG | ak::RETURN_SND;
        }
    }
    if outn == MACH_MSG_TYPE_POLYMORPHIC {
        akbsend |= ak::SERVER_ARG | ak::SEND_RCV;
        akbreturn |= ak::USER_ARG | ak::RETURN_RCV;
        if is_kernel_server {
            akbreturn |= ak::SERVER_ARG | ak::RETURN_SND;
        }
    }
    let kind = rt[id].kind;
    if ak::check(kind, ak::SEND) {
        poly.kind |= kind & akbsend;
    }
    if ak::check(kind, ak::RETURN) {
        poly.kind |= kind & akbreturn;
    }
    let pid = rt.insert_after(id, poly);
    rt[id].poly = Some(pid);
}

/// `rtAddDeallocArg`: Dealloc[] lets the caller choose, per call.
fn add_dealloc_arg(rt: &mut Routine, types: &mut Types, id: ArgId) {
    let dty = types.make_dealloc_type();
    let mut d = Arg::new(format!("{}Dealloc", rt[id].name), ak::E_DEALLOC, dty);
    d.parent = Some(id);
    let kind = rt[id].kind;
    if ak::check(kind, ak::SEND) {
        d.kind |= kind & (ak::USER_ARG | ak::SEND | ak::SEND_SND);
    }
    if ak::check(kind, ak::RETURN) {
        d.kind |= kind & (ak::SERVER_ARG | ak::RETURN | ak::RETURN_SND);
        d.by_reference_server = true;
    }
    let did = rt.insert_after(id, d);
    rt[id].dealloc = Some(did);
}

/// `rtDetectKPDArg`: kernel-processed data (ports, OOL memory, OOL ports)
/// travels as descriptors, not in the body.
fn detect_kpd_arg(rt: &mut Routine, types: &mut Types, id: ArgId) {
    let ty = rt[id].ty;
    if !types[ty].is_kern_proc_data() {
        return;
    }
    let a = &mut rt.args[id];
    if ak::check(a.kind, ak::SEND_BODY) {
        a.kind &= !ak::SEND_BODY;
        a.kind |= ak::SEND_KPD;
    }
    if ak::check(a.kind, ak::RETURN_BODY) {
        a.kind &= !ak::RETURN_BODY;
        a.kind |= ak::RETURN_KPD;
    }
    let (kpd, s) = if types[ty].in_line {
        (Kpd::Port, "mach_msg_port_descriptor_t")
    } else if types[ty].port_type {
        (Kpd::OolPorts, "mach_msg_ool_ports_descriptor_t")
    } else {
        (Kpd::Ool, "mach_msg_ool_descriptor_t")
    };
    a.kpd = Some(kpd);
    types[ty].kpd_type = Some(s.into());
}

/// `rtAddDummyReplyPort`: inserted after the request port.
fn add_dummy_reply_port(rt: &mut Routine, types: &mut Types, ty: TypeId) {
    let mut a = Arg::new("dummy ReplyPort arg", ak::E_REPLY_PORT, ty);
    a.var_name = Some("dummy ReplyPort arg".into());
    let id = match rt.request_port {
        Some(rp) => rt.insert_after(rp, a),
        None => rt.prepend(a),
    };
    rt.reply_port = Some(id);
    set_arg_defaults(rt, types, id);
}

/// `rtAddMsgOption`: inserted first.
fn add_msg_option(rt: &mut Routine, types: &mut Types, name: String) {
    let mut a = Arg::new("dummy MsgOption arg", ak::E_MSG_OPTION, types.msg_option);
    a.var_name = Some(name);
    let id = rt.prepend(a);
    rt.msg_option = Some(id);
    set_arg_defaults(rt, types, id);
}

/// `rtAddWaitTime`: inserted after the msg option.
fn add_wait_time(rt: &mut Routine, types: &mut Types, name: String, kind: u32) {
    let mut a = Arg::new("dummy WaitTime arg", kind, types.wait_time);
    a.var_name = Some(name);
    let id = match rt.msg_option {
        Some(mo) => rt.insert_after(mo, a),
        None => rt.prepend(a),
    };
    rt.wait_time = Some(id);
    set_arg_defaults(rt, types, id);
}

/// `rtCheckSimple`: a message is complex iff it carries kernel-processed data.
fn check_simple(rt: &Routine, types: &Types, mask: u32) -> bool {
    !rt.iter()
        .any(|a| a.has(mask) && types[a.ty].is_kern_proc_data())
}

/// `machine_alignment(SZ, ESZ)`: word-align `SZ`, then add `ESZ`.
pub fn machine_alignment(size: u32, esz: u32) -> u32 {
    ((size + 3) & !3) + esz
}

/// `rtCheckFit`: does the message fit the on-stack limit?
fn check_fit(rt: &Routine, types: &Types, env: &CheckEnv, mask: u32) -> (bool, bool, u32) {
    let mut uselim = false;
    let mut size: u32 = 24; // sizeof(mach_msg_header_t)
    if !rt.simple_request {
        size = machine_alignment(size, 4);
    }
    for a in rt.iter() {
        if a.has(mask) {
            let it = &types[a.ty];
            size = machine_alignment(size, it.min_type_size);
            if it.native {
                uselim = true;
            } else if it.is_variable_sized_untyped() {
                size = machine_alignment(size, it.type_size);
                size += it.pad_size;
            }
        }
    }
    let max = env.opts.max_mess_size_on_stack.unwrap_or(-1);
    let limit = env.opts.user_type_limit.unwrap_or(-1);
    if max == -1 {
        (true, false, size)
    } else if size as i64 > max as i64 {
        (false, false, size)
    } else if !uselim {
        (true, false, size)
    } else if limit == -1 {
        (false, false, size)
    } else if size as i64 + limit as i64 > max as i64 {
        (false, true, size)
    } else {
        (true, true, size)
    }
}

/// `rtCheckOverwrite`: mark the OOL out args that need a scatter-list entry.
fn check_overwrite(rt: &mut Routine, types: &Types) {
    let mut howmany = rt.overwrite;
    for id in rt.ids() {
        if rt[id].has(ak::RETURN_KPD) && !types[rt[id].ty].in_line {
            rt[id].kind |= ak::OVERWRITE;
            if rt[id].flags & fl::OVERWRITE != 0 {
                howmany -= 1;
            }
            if howmany == 0 {
                return;
            }
        }
    }
}

/// `rtCheckVariable`: positions of arguments relative to variable-sized
/// inline data, which shifts everything after it.
fn check_variable(rt: &mut Routine) {
    let mut num_req = 0u32;
    let mut num_rep = 0u32;
    let mut max_req = 0u32;
    let mut max_rep = 0u32;
    for id in rt.ids() {
        let parent = rt[id].parent;
        let top = match parent {
            None => true,
            Some(p) => rt[p].has(ak::SEND_KPD | ak::RETURN_KPD),
        };
        if top {
            if rt[id].has_all(ak::SEND | ak::SEND_BODY) {
                rt[id].request_pos = num_req;
                max_req = num_req;
                if rt[id].has(ak::VARIABLE) {
                    num_req += 1;
                }
            }
            if rt[id].has_all(ak::RETURN | ak::RETURN_BODY) {
                rt[id].reply_pos = num_rep;
                max_rep = num_rep;
                if rt[id].has(ak::VARIABLE) {
                    num_rep += 1;
                }
            }
        } else {
            let p = parent.unwrap();
            rt[id].request_pos = rt[p].request_pos;
            rt[id].reply_pos = rt[p].reply_pos;
        }
        // Out values following variable-sized data can't be stored
        // directly into the reply message.
        if rt[id].has_all(ak::RETURN_SND | ak::RETURN_BODY)
            && !rt[id].has(ak::REPLY_COPY | ak::VAR_NEEDED)
            && rt[id].reply_pos > 0
        {
            rt[id].kind |= ak::VAR_NEEDED;
        }
    }
    rt.num_request_var = num_req;
    rt.num_reply_var = num_rep;
    rt.max_request_pos = max_req;
    rt.max_reply_pos = max_rep;
}

/// `rtCheckDestroy`
fn check_destroy(rt: &mut Routine, types: &Types) {
    for id in rt.ids() {
        let it = &types[rt[id].ty];
        if rt[id].has(ak::SEND_RCV)
            && !rt[id].has(ak::RETURN_SND)
            && (it.destructor.is_some() || it.is_mig_inline_emul())
        {
            rt[id].kind |= ak::DESTROY;
        }
        let arg_is_in = rt[id].ident() == ak::E_NORMAL && rt[id].has(ak::REQUEST);
        if arg_is_in
            && rt[id].has(ak::SEND_KPD | ak::RETURN_KPD)
            && rt[id].kpd == Some(Kpd::Ool)
            && rt[id].flags & fl::AUTO != 0
        {
            rt[id].kind |= ak::DESTROY;
        }
    }
}

/// `rtAddByReference`
fn add_by_reference(rt: &mut Routine, types: &Types, env: &CheckEnv) {
    for id in rt.ids() {
        let it = &types[rt[id].ty];
        if rt[id].has(ak::RETURN_RCV) && it.is_struct {
            rt[id].by_reference_user = true;
            // A CountInOut arg is not akbReturnRcv itself.
            if let Some(c) = rt[id].cinout {
                rt[c].by_reference_user = true;
            }
        }
        if (rt[id].has(ak::RETURN_SND)
            || (rt[id].has(ak::SERVER_IMPLICIT)
                && rt[id].has(ak::RETURN_RCV)
                && rt[id].has(ak::SEND_RCV)))
            && it.is_struct
        {
            rt[id].by_reference_server = true;
            if env.opts.is_kernel_server && it.is_kern_proc_data() {
                // PAC: the address of a signed pointer can't be taken.
                rt[id].kind |= ak::VAR_NEEDED;
            }
        }
    }
}

/// `rtSuffixExtArg`: the descriptor field holding a KPD's value.
fn suffix_ext_arg(rt: &mut Routine, types: &Types) -> Result<(), String> {
    for id in rt.ids() {
        if rt[id].has(ak::SEND_KPD | ak::RETURN_KPD) {
            let sub = if types[rt[id].ty].is_multiple_kpd() {
                "[0]"
            } else {
                ""
            };
            let field = match rt[id].kpd {
                Some(Kpd::Port) => format!("{sub}.name"),
                Some(Kpd::Ool | Kpd::OolPorts) => format!("{sub}.address"),
                None => return Err("Type of kernel processed data unknown".into()),
            };
            rt[id].suffix = Some(format!("{}{}", rt[id].msg_field(), field));
        } else if let Some(p) = rt[id].parent {
            let ident = rt[id].ident();
            if !rt[p].has(ak::SEND_KPD | ak::RETURN_KPD) {
                continue;
            }
            let sub = if types[rt[p].ty].is_multiple_kpd() {
                "[0]"
            } else {
                ""
            };
            if ident == ak::E_POLY {
                match rt[p].kpd {
                    Some(Kpd::Port | Kpd::OolPorts) => {
                        rt[id].suffix = Some(format!("{}{sub}.disposition", rt[p].msg_field()));
                    }
                    _ => return Err("Type of kernel processed data inconsistent".into()),
                }
            } else if ident == ak::E_DEALLOC {
                match rt[p].kpd {
                    Some(Kpd::Ool | Kpd::OolPorts) => {
                        rt[id].suffix = Some(format!("{}{sub}.deallocate", rt[p].msg_field()));
                    }
                    _ => return Err("Type of kernel processed data inconsistent".into()),
                }
            }
        }
    }
    Ok(())
}

/// `rtAddSameCount`: a SameCount array shares its neighbour's count.
fn add_same_count(rt: &mut Routine, types: &mut Types) -> Result<(), String> {
    for id in rt.ids() {
        if rt[id].flags & fl::SAME_COUNT == 0 {
            continue;
        }
        let it = rt[id].ty;
        let my_count = rt[id].count.ok_or("SameCount argument has no count")?;
        let reference = rt[id]
            .same_count
            .ok_or_else(|| format!("{}: SameCount with no preceding argument", rt[id].name))?;
        let ref_count = rt[reference]
            .count
            .ok_or_else(|| format!("{}: SameCount reference has no count", rt[id].name))?;
        let mut tmp = rt[ref_count].clone();
        let var_needed = rt[my_count].kind & ak::VAR_NEEDED;
        tmp.kind = ak::E_SAME_COUNT | var_needed;
        rt[ref_count].kind |= var_needed;
        tmp.next = rt[my_count].next;
        tmp.multiplier = rt[my_count].multiplier;
        tmp.ty = rt[my_count].ty;
        tmp.parent = Some(id);
        let tid = rt.push(tmp);
        rt[id].count = Some(tid);
        rt[id].next = Some(tid);
        // The count of these arrays is not akbRequest, so its size is
        // embedded in the array's (shared!) type.
        if types[it].is_variable_sized_untyped() {
            types[it].min_type_size = 0;
        }
        let cty = rt[tid].ty;
        types[cty].min_type_size = 0;
        types[cty].type_size = 0;
    }
    Ok(())
}

/// `rtProcessRetCode`: RetCode != 0 only travels in mig_reply_error_t, so a
/// reply with arguments keeps it in a local variable.
fn process_ret_code(rt: &mut Routine) {
    if !rt.one_way && !rt.simple_reply {
        let id = rt.ret_code;
        rt[id].kind &= !ak::REPLY;
        rt[id].kind |= ak::VAR_NEEDED;
    }
    if let Some(id) = rt.retc_arg {
        if !rt.simple_request {
            rt[id].kind = ak::E_RET_CODE | ak::USER_ARG | ak::SERVER_ARG | ak::SEND_RCV;
        }
    }
}

/// `rtProcessNdrCode`: an NDR record precedes any untyped data.
fn process_ndr_code(rt: &mut Routine, types: &Types) {
    let ndr = rt.ndr_code;
    const NDR_SEND: u32 = ak::REQUEST | ak::SEND | ak::SEND_SND | ak::SEND_BODY;
    const NDR_RCV: u32 = ak::REPLY | ak::REPLY_INIT | ak::RETURN | ak::RETURN_BODY;
    rt[ndr].kind |= NDR_SEND | NDR_RCV;

    let rest = {
        let mut v = Vec::new();
        let mut cur = rt[ndr].next;
        while let Some(id) = cur {
            v.push(id);
            cur = rt[id].next;
        }
        v
    };
    let child_ok = |rt: &Routine, id: ArgId| {
        rt[id].parent.is_none()
            || rt[id].ident() == ak::E_COUNT
            || rt[id].ident() == ak::E_COUNT_IN_OUT
    };
    let mut found = false;
    for &id in &rest {
        if rt[id].has(ak::SEND_RCV | ak::SEND_BODY)
            && !rt[id].has(ak::SERVER_IMPLICIT)
            && !types[rt[id].ty].port_type
            && child_ok(rt, id)
        {
            rt[id].kind |= ak::SEND_NDR;
            found = true;
        }
    }
    if !found {
        rt[ndr].kind &= !NDR_SEND;
    }
    let mut found = false;
    if !rt.one_way {
        for &id in &rest {
            let is_ret = id == rt.ret_code;
            if (is_ret && rt[id].has(ak::REPLY))
                || (!is_ret
                    && rt[id].has(ak::RETURN_RCV | ak::RETURN_BODY)
                    && !rt[id].has(ak::USER_IMPLICIT)
                    && !types[rt[id].ty].port_type
                    && child_ok(rt, id))
            {
                rt[id].kind |= ak::RETURN_NDR;
                found = true;
            }
        }
    }
    if !found && !rt[rt.ret_code].has(ak::REPLY) {
        rt[ndr].kind &= !NDR_RCV;
    }
}

/// `rtProcessMsgOption`: ask for the trailer elements the user receives.
fn process_msg_option(rt: &mut Routine) {
    let (mut seqno, mut sec, mut audit, mut ctx) = (false, false, false, false);
    for a in rt.iter() {
        if a.has_all(ak::RETURN | ak::USER_IMPLICIT) {
            match a.ident() {
                ak::E_MSG_SEQNO => seqno = true,
                ak::E_SEC_TOKEN => sec = true,
                ak::E_AUDIT_TOKEN => audit = true,
                ak::E_CONTEXT_TOKEN => ctx = true,
                _ => {}
            }
        }
    }
    let mo = rt.msg_option.expect("msg option");
    let base = rt[mo].var_name().to_string();
    let extra = if ctx {
        "|MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_CTX)"
    } else if audit {
        "|MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT)"
    } else if sec {
        "|MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_SENDER)"
    } else if seqno {
        "|MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_SEQNO)"
    } else {
        ""
    };
    rt[mo].var_name = Some(format!("{base}{extra}"));
}

/// `rtAddArgSegment`: which pointer reaches each argument's field. With
/// mach_msg2 KernelServer stubs the header and descriptors (kernel data)
/// and the body (user data) are separate buffers.
fn add_arg_segment(rt: &mut Routine, types: &Types, o: &Options) {
    for id in rt.ids() {
        let kpd = types[rt[id].ty].is_kern_proc_data()
            || (rt[id].ident() == ak::E_POLY
                && rt[id]
                    .parent
                    .map(|p| types[rt[p].ty].is_kern_proc_data())
                    .unwrap_or(false));
        let pos = rt[id].request_pos;
        let a = &mut rt.args[id];
        if !o.use_mach_msg2 {
            a.in_segment = format!("In{pos}P");
            a.out_segment = "OutP".into();
        } else if kpd {
            a.in_segment = "InKP".into();
            a.out_segment = "OutKP".into();
        } else {
            a.in_segment = format!("In{pos}UP");
            a.out_segment = "OutUP".into();
        }
    }
}
