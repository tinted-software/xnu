// SPDX-License-Identifier: MIT
// Semantic lowering: walk the parsed statements in order, applying the
// global declarations and checking each routine (`rtCheckRoutine`) with the
// option state in effect at its declaration, as the original parser does.

use crate::ast::*;
use crate::diag::Diag;
use crate::global::Options;
use crate::routine::{self, CheckEnv, Routine};
use crate::types::Types;

/// The checked routines of a subsystem, plus `rtNumber`: the number of
/// message ids it spans (routines and `skip`s).
pub struct Module {
    pub routines: Vec<Routine>,
    pub rt_number: u32,
}

/// Walk parsed statements, fill in `Options` from the semantic declarations
/// and check every routine.
pub fn lower(
    stmts: &[Statement],
    opts: &mut Options,
    types: &mut Types,
    diag: &mut Diag,
) -> Module {
    let mut module = Module {
        routines: Vec::new(),
        rt_number: 0,
    };
    for stmt in stmts {
        match stmt {
            Statement::Subsystem {
                name,
                base,
                is_kernel_user,
                is_kernel_server,
            } => {
                if opts.subsystem_name.is_some() {
                    diag.error_noloc(&format!(
                        "previous Subsystem declaration ({}) will be ignored",
                        opts.subsystem_name.as_deref().unwrap_or("?")
                    ));
                }
                opts.subsystem_name = Some(name.clone());
                opts.subsystem_base = *base;
                if *is_kernel_user {
                    if opts.is_kernel_user {
                        diag.error_noloc("duplicate KernelUser keyword");
                    }
                    if !opts.use_msg_rpc {
                        diag.error_noloc("with KernelUser the -R option is meaningless");
                        opts.use_msg_rpc = true;
                    }
                    opts.is_kernel_user = true;
                }
                if *is_kernel_server {
                    if opts.is_kernel_server {
                        diag.error_noloc("duplicate KernelServer keyword");
                    }
                    opts.is_kernel_server = true;
                }
            }
            Statement::WaitTime(s) => {
                opts.wait_time = Some(s.clone());
            }
            Statement::NoWaitTime => {
                opts.wait_time = None;
            }
            Statement::SendTime(s) => {
                opts.send_time = Some(s.clone());
            }
            Statement::NoSendTime => {
                opts.send_time = None;
            }
            Statement::MsgOption(o) => {
                opts.msg_option = o.clone();
            }
            Statement::UseSpecialReplyPort(v) => {
                opts.use_special_reply_port = *v;
                if *v {
                    opts.has_use_special_reply_port = true;
                }
            }
            Statement::ConsumeOnSendError(v) => {
                opts.consume_on_send_error = *v;
                if *v != ConsumeOnSendError::None {
                    opts.has_consume_on_send_error = true;
                }
            }
            Statement::UserTypeLimit(n) => {
                opts.user_type_limit = Some(*n as i32);
            }
            Statement::OnStackLimit(n) => {
                opts.max_mess_size_on_stack = Some(*n as i32);
            }
            Statement::ErrorProc(s) => {
                opts.error_proc = s.clone();
            }
            Statement::ServerPrefix(s) => {
                opts.server_prefix = s.clone();
            }
            Statement::UserPrefix(s) => {
                opts.user_prefix = s.clone();
            }
            Statement::ServerDemux(s) => {
                opts.server_demux = Some(s.clone());
            }
            Statement::RCSDecl(s) => {
                opts.rcs_id = Some(s.clone());
            }
            Statement::Routine(r) => {
                let env = CheckEnv {
                    opts,
                    quiet: opts.quiet,
                };
                match routine::check_routine(r, module.rt_number, types, &env) {
                    Ok(rt) => module.routines.push(rt),
                    Err(e) => diag.error_noloc(&e),
                }
                module.rt_number += 1;
            }
            Statement::Skip => {
                module.rt_number += 1;
            }
            Statement::TypeDecl { .. } | Statement::Import { .. } => {}
        }
    }
    module
}
