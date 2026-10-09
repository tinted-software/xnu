// SPDX-License-Identifier: MIT
// Code generation sub-modules

use crate::ast::Statement;
use crate::global::Options;
use crate::routine::Routine;
use crate::types::Types;

pub mod header;
pub mod server;
pub mod user;
pub mod utils;

/// Everything the writers read: the statement list (for imports), the
/// checked routines, the type arena and the final global options.
pub struct Gen<'a> {
    pub stmts: &'a [Statement],
    pub routines: &'a [Routine],
    /// `rtNumber`: routines plus skipped message ids.
    pub rt_number: u32,
    pub types: &'a Types,
    pub opts: &'a Options,
}

impl Gen<'_> {
    pub fn subsystem(&self) -> &str {
        self.opts.subsystem_name.as_deref().unwrap_or("")
    }

    /// `ServerSubsys`
    pub fn server_subsys(&self) -> String {
        format!("{}{}_subsystem", self.opts.server_prefix, self.subsystem())
    }

    /// `ServerDemux`
    pub fn server_demux(&self) -> String {
        self.opts
            .server_demux
            .clone()
            .unwrap_or_else(|| format!("{}_server", self.subsystem()))
    }
}
