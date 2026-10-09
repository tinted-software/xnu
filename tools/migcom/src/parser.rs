// SPDX-License-Identifier: MIT
// Recursive-descent parser for .defs files

use crate::ast::*;
use crate::diag::Diag;
use crate::lexer::{Spanned, Token};
use crate::types::{fl, TypeId, Types};

pub struct Parser<'src> {
    tokens: &'src [Spanned],
    pos: usize,
    pub diag: &'src mut Diag,
    pub types: Types,
}

impl<'src> Parser<'src> {
    pub fn new(tokens: &'src [Spanned], diag: &'src mut Diag) -> Self {
        Self {
            tokens,
            pos: 0,
            diag,
            types: Types::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Token stream helpers
    // -----------------------------------------------------------------------

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|s| &s.token)
    }

    fn peek_span(&self) -> std::ops::Range<usize> {
        self.tokens
            .get(self.pos)
            .map(|s| s.span.clone())
            .unwrap_or(0..0)
    }

    #[allow(dead_code)]
    fn advance(&mut self) -> Option<&Spanned> {
        let t = self.tokens.get(self.pos);
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn at_end(&self) -> bool {
        self.pos >= self.tokens.len()
    }

    fn expect(&mut self, expected: &Token) -> bool {
        if self.peek() == Some(expected) {
            self.pos += 1;
            true
        } else {
            let sp = self.peek_span();
            let got = self
                .peek()
                .map(|t| format!("{t:?}"))
                .unwrap_or_else(|| "EOF".into());
            self.diag
                .error(sp, &format!("expected {expected:?}, got {got}"));
            false
        }
    }

    fn expect_identifier(&mut self) -> Option<String> {
        match self.peek() {
            Some(Token::Identifier(s)) => {
                let s = s.clone();
                self.pos += 1;
                Some(s)
            }
            _ => {
                let sp = self.peek_span();
                self.diag.error(sp, "expected identifier");
                None
            }
        }
    }

    fn expect_number(&mut self) -> Option<u32> {
        match self.peek() {
            Some(Token::Number(n)) => {
                let n = *n;
                self.pos += 1;
                Some(n)
            }
            _ => {
                let sp = self.peek_span();
                self.diag.error(sp, "expected number");
                None
            }
        }
    }

    fn expect_string(&mut self) -> Option<String> {
        match self.peek() {
            Some(Token::StringLit(s) | Token::QStringLit(s)) => {
                let s = s.clone();
                self.pos += 1;
                Some(s)
            }
            Some(Token::Identifier(s)) => {
                let s = s.clone();
                self.pos += 1;
                Some(s)
            }
            _ => {
                let sp = self.peek_span();
                self.diag.error(sp, "expected string");
                None
            }
        }
    }

    fn expect_filename(&mut self) -> Option<String> {
        match self.peek() {
            Some(Token::FileName(s) | Token::QStringLit(s)) => {
                let s = s.clone();
                self.pos += 1;
                Some(s)
            }
            _ => {
                let sp = self.peek_span();
                self.diag.error(sp, "expected filename");
                None
            }
        }
    }

    fn expect_qstring(&mut self) -> Option<String> {
        match self.peek() {
            Some(Token::QStringLit(s)) => {
                let s = s.clone();
                self.pos += 1;
                Some(s)
            }
            _ => {
                let sp = self.peek_span();
                self.diag.error(sp, "expected quoted string");
                None
            }
        }
    }

    // Skip to next semicolon for error recovery
    fn sync_to_semi(&mut self) {
        while !self.at_end() {
            if self.peek() == Some(&Token::Semi) {
                self.pos += 1;
                break;
            }
            self.pos += 1;
        }
    }

    // -----------------------------------------------------------------------
    // Top-level parse
    // -----------------------------------------------------------------------

    pub fn parse_statements(&mut self) -> Vec<Statement> {
        let mut stmts = Vec::new();
        while !self.at_end() {
            if self.peek() == Some(&Token::Semi) {
                self.pos += 1;
                continue;
            }
            match self.parse_statement() {
                Some(s) => stmts.push(s),
                None => self.sync_to_semi(),
            }
        }
        stmts
    }

    fn parse_statement(&mut self) -> Option<Statement> {
        let sp = self.peek_span();
        let stmt = match self.peek()? {
            Token::Subsystem => self.parse_subsystem(),
            Token::WaitTime => self.parse_waittime(),
            Token::SendTime => self.parse_sendtime(),
            Token::NoWaitTime => {
                self.pos += 1;
                Some(Statement::NoWaitTime)
            }
            Token::NoSendTime => {
                self.pos += 1;
                Some(Statement::NoSendTime)
            }
            Token::MsgOption => self.parse_msgoption(),
            Token::UseSpecialReplyPort => self.parse_use_special_reply(),
            Token::ConsumeOnSendError => self.parse_consume_on_send_error(),
            Token::UserTypeLimit => {
                self.pos += 1;
                let n = self.expect_number()?;
                Some(Statement::UserTypeLimit(n))
            }
            Token::OnStackLimit => {
                self.pos += 1;
                let n = self.expect_number()?;
                Some(Statement::OnStackLimit(n))
            }
            Token::ErrorProc => {
                self.pos += 1;
                let id = self.expect_identifier()?;
                Some(Statement::ErrorProc(id))
            }
            Token::ServerPrefix => {
                self.pos += 1;
                let id = self.expect_identifier()?;
                Some(Statement::ServerPrefix(id))
            }
            Token::UserPrefix => {
                self.pos += 1;
                let id = self.expect_identifier()?;
                Some(Statement::UserPrefix(id))
            }
            Token::ServerDemux => {
                self.pos += 1;
                let id = self.expect_identifier()?;
                Some(Statement::ServerDemux(id))
            }
            Token::Type => self.parse_type_decl(),
            Token::Routine | Token::SimpleRoutine => self.parse_routine_decl(),
            Token::Skip => {
                self.pos += 1;
                Some(Statement::Skip)
            }
            Token::Import | Token::UImport | Token::SImport | Token::IImport | Token::DImport => {
                self.parse_import()
            }
            Token::RCSId => self.parse_rcsdecl(),
            other => {
                let msg = format!("unexpected token {other:?}");
                self.diag.error(sp, &msg);
                return None;
            }
        }?;
        self.expect(&Token::Semi);
        Some(stmt)
    }

    // -----------------------------------------------------------------------
    // Individual statement parsers
    // -----------------------------------------------------------------------

    fn parse_subsystem(&mut self) -> Option<Statement> {
        self.pos += 1; // consume `subsystem`
        let mut is_kernel_user = false;
        let mut is_kernel_server = false;
        // optional modifiers
        loop {
            match self.peek() {
                Some(Token::KernelUser) => {
                    is_kernel_user = true;
                    self.pos += 1;
                }
                Some(Token::KernelServer) => {
                    is_kernel_server = true;
                    self.pos += 1;
                }
                _ => break,
            }
        }
        let name = self.expect_identifier()?;
        let base = self.expect_number()?;
        Some(Statement::Subsystem {
            name,
            base,
            is_kernel_user,
            is_kernel_server,
        })
    }

    fn parse_waittime(&mut self) -> Option<Statement> {
        self.pos += 1;
        let s = self.expect_string()?;
        Some(Statement::WaitTime(s))
    }

    fn parse_sendtime(&mut self) -> Option<Statement> {
        self.pos += 1;
        let s = self.expect_string()?;
        Some(Statement::SendTime(s))
    }

    fn parse_msgoption(&mut self) -> Option<Statement> {
        self.pos += 1;
        let s = self.expect_string()?;
        if s == "MACH_MSG_OPTION_NONE" {
            Some(Statement::MsgOption(None))
        } else {
            Some(Statement::MsgOption(Some(s)))
        }
    }

    fn parse_use_special_reply(&mut self) -> Option<Statement> {
        self.pos += 1;
        let n = self.expect_number()?;
        Some(Statement::UseSpecialReplyPort(n != 0))
    }

    fn parse_consume_on_send_error(&mut self) -> Option<Statement> {
        self.pos += 1;
        let s = self.expect_string()?;
        let val = match s.to_lowercase().as_str() {
            "none" => ConsumeOnSendError::None,
            "timeout" => ConsumeOnSendError::Timeout,
            "any" => ConsumeOnSendError::Any,
            _ => {
                let sp = self.peek_span();
                self.diag.error(sp, "invalid ConsumeOnSendError value");
                return None;
            }
        };
        Some(Statement::ConsumeOnSendError(val))
    }

    /// `TypeDecl: syType NamedTypeSpec` — name the type (`itTypeDecl`) and
    /// enter it in the symbol table (`itInsert`).
    fn parse_type_decl(&mut self) -> Option<Statement> {
        self.pos += 1; // consume `type`
        let name = self.expect_identifier()?;
        self.expect(&Token::Equal);
        let ty = self.parse_trans_type_spec()?;
        self.types.type_decl(&name, ty);
        self.types.insert(&name, ty);
        Some(Statement::TypeDecl { name })
    }

    fn parse_import(&mut self) -> Option<Statement> {
        let kind = match self.peek()? {
            Token::Import => ImportKind::Import,
            Token::UImport => ImportKind::UImport,
            Token::SImport => ImportKind::SImport,
            Token::IImport => ImportKind::IImport,
            Token::DImport => ImportKind::DImport,
            _ => unreachable!(),
        };
        self.pos += 1;
        let filename = self.expect_filename()?;
        Some(Statement::Import { kind, filename })
    }

    fn parse_rcsdecl(&mut self) -> Option<Statement> {
        self.pos += 1; // consume `RCSId`
        let s = self.expect_qstring()?;
        Some(Statement::RCSDecl(s))
    }

    // -----------------------------------------------------------------------
    // Routine parsing
    // -----------------------------------------------------------------------

    fn parse_routine_decl(&mut self) -> Option<Statement> {
        let kind = match self.peek()? {
            Token::Routine => RoutineKind::Routine,
            Token::SimpleRoutine => RoutineKind::SimpleRoutine,
            _ => unreachable!(),
        };
        self.pos += 1;
        let name = self.expect_identifier()?;
        let args = self.parse_arguments()?;
        Some(Statement::Routine(Routine { kind, name, args }))
    }

    fn parse_arguments(&mut self) -> Option<Vec<Argument>> {
        self.expect(&Token::LParen);
        if self.peek() == Some(&Token::RParen) {
            self.pos += 1;
            return Some(vec![]);
        }
        let list = self.parse_argument_list()?;
        self.expect(&Token::RParen);
        Some(list)
    }

    fn parse_argument_list(&mut self) -> Option<Vec<Argument>> {
        let mut args = Vec::new();
        loop {
            // On error inside an argument, skip to the next `;` or `)` and keep going
            // so one bad type reference doesn't kill the whole routine.
            match self.parse_single_argument() {
                Some(arg) => args.push(arg),
                None => {
                    // consume up to `;` or `)`
                    while !self.at_end() {
                        match self.peek() {
                            Some(Token::Semi) | Some(Token::RParen) => break,
                            _ => {
                                self.pos += 1;
                            }
                        }
                    }
                }
            }
            if self.peek() == Some(&Token::Semi) {
                self.pos += 1;
                if self.peek() == Some(&Token::RParen) {
                    break;
                }
            } else {
                break;
            }
        }
        Some(args)
    }

    fn parse_single_argument(&mut self) -> Option<Argument> {
        // In the MIG grammar an argument is either:
        //   Direction Identifier : Type [Flags]    — normal
        //   DirectionKeyword : Type                — keyword doubles as name (e.g. requestPort)
        //   TrImplKeyword Identifier : Type        — trailer (ServerImpl / UserImpl)
        //
        // We disambiguate by peeking at token[pos+1]: if it is `:` the direction
        // keyword is being used as both direction AND name.
        let (direction, name) = self.parse_direction_and_name()?;
        self.expect(&Token::Colon);
        let ty = self.parse_argument_type()?;
        let flags = self.parse_ipc_flags();
        Some(Argument {
            name,
            direction,
            ty,
            flags,
        })
    }

    /// Returns (direction, name) for one argument, handling the dual-role keywords.
    fn parse_direction_and_name(&mut self) -> Option<(Direction, String)> {
        // Keyword directions that can double as the argument name (no separate identifier follows):
        // requestPort, replyPort, sReplyPort, uReplyPort, waitTime, sendTime, msgOption,
        // secToken, serverSecToken, userSecToken, auditToken, serverAuditToken,
        // userAuditToken, serverContextToken, msgSeqno, serverImpl, userImpl.
        //
        // `in`, `out`, `inout` always take a separate identifier after them.
        let next_is_colon = self
            .tokens
            .get(self.pos + 1)
            .map(|s| s.token == Token::Colon)
            .unwrap_or(false);

        match self.peek() {
            // Pure direction prefixes — always followed by a separate identifier
            Some(Token::In) => {
                self.pos += 1;
                let n = self.expect_identifier()?;
                Some((Direction::In, n))
            }
            Some(Token::Out) => {
                self.pos += 1;
                let n = self.expect_identifier()?;
                Some((Direction::Out, n))
            }
            Some(Token::InOut) => {
                self.pos += 1;
                let n = self.expect_identifier()?;
                Some((Direction::InOut, n))
            }

            // Dual-role direction keywords: if next token is `:`, the keyword IS the name
            Some(Token::RequestPort) => {
                self.pos += 1;
                if next_is_colon {
                    Some((Direction::RequestPort, "requestPort".into()))
                } else {
                    let n = self.expect_identifier()?;
                    Some((Direction::RequestPort, n))
                }
            }
            Some(Token::ReplyPort) => {
                self.pos += 1;
                if next_is_colon {
                    Some((Direction::ReplyPort, "replyPort".into()))
                } else {
                    let n = self.expect_identifier()?;
                    Some((Direction::ReplyPort, n))
                }
            }
            Some(Token::SReplyPort) => {
                self.pos += 1;
                if next_is_colon {
                    Some((Direction::SReplyPort, "sReplyPort".into()))
                } else {
                    let n = self.expect_identifier()?;
                    Some((Direction::SReplyPort, n))
                }
            }
            Some(Token::UReplyPort) => {
                self.pos += 1;
                if next_is_colon {
                    Some((Direction::UReplyPort, "uReplyPort".into()))
                } else {
                    let n = self.expect_identifier()?;
                    Some((Direction::UReplyPort, n))
                }
            }
            Some(Token::WaitTime) => {
                self.pos += 1;
                if next_is_colon {
                    Some((Direction::WaitTime, "waitTime".into()))
                } else {
                    let n = self.expect_identifier()?;
                    Some((Direction::WaitTime, n))
                }
            }
            Some(Token::SendTime) => {
                self.pos += 1;
                if next_is_colon {
                    Some((Direction::SendTime, "sendTime".into()))
                } else {
                    let n = self.expect_identifier()?;
                    Some((Direction::SendTime, n))
                }
            }
            Some(Token::MsgOption) => {
                self.pos += 1;
                if next_is_colon {
                    Some((Direction::MsgOption, "msgOption".into()))
                } else {
                    let n = self.expect_identifier()?;
                    Some((Direction::MsgOption, n))
                }
            }
            Some(Token::SecToken) => {
                self.pos += 1;
                if next_is_colon {
                    Some((Direction::SecToken, "secToken".into()))
                } else {
                    let n = self.expect_identifier()?;
                    Some((Direction::SecToken, n))
                }
            }
            Some(Token::ServerSecToken) => {
                self.pos += 1;
                if next_is_colon {
                    Some((Direction::ServerSecToken, "serverSecToken".into()))
                } else {
                    let n = self.expect_identifier()?;
                    Some((Direction::ServerSecToken, n))
                }
            }
            Some(Token::UserSecToken) => {
                self.pos += 1;
                if next_is_colon {
                    Some((Direction::UserSecToken, "userSecToken".into()))
                } else {
                    let n = self.expect_identifier()?;
                    Some((Direction::UserSecToken, n))
                }
            }
            Some(Token::AuditToken) => {
                self.pos += 1;
                if next_is_colon {
                    Some((Direction::AuditToken, "auditToken".into()))
                } else {
                    let n = self.expect_identifier()?;
                    Some((Direction::AuditToken, n))
                }
            }
            Some(Token::ServerAuditToken) => {
                self.pos += 1;
                if next_is_colon {
                    Some((Direction::ServerAuditToken, "serverAuditToken".into()))
                } else {
                    let n = self.expect_identifier()?;
                    Some((Direction::ServerAuditToken, n))
                }
            }
            Some(Token::UserAuditToken) => {
                self.pos += 1;
                if next_is_colon {
                    Some((Direction::UserAuditToken, "userAuditToken".into()))
                } else {
                    let n = self.expect_identifier()?;
                    Some((Direction::UserAuditToken, n))
                }
            }
            Some(Token::ServerContextToken) => {
                self.pos += 1;
                if next_is_colon {
                    Some((Direction::ServerContextToken, "serverContextToken".into()))
                } else {
                    let n = self.expect_identifier()?;
                    Some((Direction::ServerContextToken, n))
                }
            }
            Some(Token::MsgSeqno) => {
                self.pos += 1;
                if next_is_colon {
                    Some((Direction::MsgSeqno, "msgSeqno".into()))
                } else {
                    let n = self.expect_identifier()?;
                    Some((Direction::MsgSeqno, n))
                }
            }
            Some(Token::ServerImpl) => {
                self.pos += 1;
                if next_is_colon {
                    Some((Direction::ServerImpl, "serverImpl".into()))
                } else {
                    let n = self.expect_identifier()?;
                    Some((Direction::ServerImpl, n))
                }
            }
            Some(Token::UserImpl) => {
                self.pos += 1;
                if next_is_colon {
                    Some((Direction::UserImpl, "userImpl".into()))
                } else {
                    let n = self.expect_identifier()?;
                    Some((Direction::UserImpl, n))
                }
            }
            // No direction keyword — plain identifier
            _ => {
                let n = self.expect_identifier()?;
                Some((Direction::None, n))
            }
        }
    }

    /// `ArgumentType`:
    ///   `: Identifier`      — the named type itself (`itLookUp`, shared)
    ///   `: NamedTypeSpec`   — `Identifier = TransTypeSpec`, named but not
    ///                         entered in the symbol table
    ///   `: NativeTypeSpec`
    ///
    /// The colon has already been consumed by the caller. Any other type
    /// spec is accepted as an anonymous `TransTypeSpec`.
    fn parse_argument_type(&mut self) -> Option<TypeId> {
        match self.peek() {
            Some(Token::Identifier(_)) => {
                let is_named_spec = self
                    .tokens
                    .get(self.pos + 1)
                    .map(|s| s.token == Token::Equal)
                    .unwrap_or(false);
                let sp = self.peek_span();
                let name = self.expect_identifier()?;
                if is_named_spec {
                    self.expect(&Token::Equal);
                    let ty = self.parse_trans_type_spec()?;
                    self.types.type_decl(&name, ty);
                    return Some(ty);
                }
                match self.types.lookup(&name) {
                    Some(ty) => Some(ty),
                    None => {
                        self.diag.error(sp, &format!("type '{name}' not defined"));
                        Some(self.types.placeholder())
                    }
                }
            }
            Some(Token::PointerTo | Token::PointerToIfNot | Token::ValueOf) => {
                self.parse_native_type_spec()
            }
            _ => self.parse_trans_type_spec(),
        }
    }

    fn parse_ipc_flags(&mut self) -> u32 {
        let mut flags = fl::NONE;
        while self.peek() == Some(&Token::Comma) {
            self.pos += 1;
            let f = match self.peek() {
                Some(Token::SameCount) => fl::SAME_COUNT,
                Some(Token::RetCode) => fl::RET_CODE,
                Some(Token::PhysicalCopy) => fl::PHYSICAL_COPY,
                Some(Token::Overwrite) => fl::OVERWRITE,
                Some(Token::Dealloc) => {
                    self.pos += 1;
                    // Dealloc[] → MAYBE_DEALLOC
                    if self.peek() == Some(&Token::LBrack) {
                        self.pos += 1;
                        self.expect(&Token::RBrack);
                        flags |= fl::MAYBE_DEALLOC;
                        continue;
                    }
                    flags |= fl::DEALLOC;
                    continue;
                }
                Some(Token::NotDealloc) => fl::NOT_DEALLOC,
                Some(Token::CountInOut) => fl::COUNT_IN_OUT,
                Some(Token::Auto) => fl::AUTO,
                Some(Token::Const) => fl::CONST,
                _ => break,
            };
            self.pos += 1;
            flags |= f;
        }
        flags
    }

    // -----------------------------------------------------------------------
    // Type spec parsing
    // -----------------------------------------------------------------------

    /// `TransTypeSpec`: a `TypeSpec` with its translation/C-type info reset
    /// (`itResetType`), followed by `intran:`/`outtran:`/`destructor:`/
    /// `ctype:`/`cusertype:`/`cservertype:` modifiers.
    fn parse_trans_type_spec(&mut self) -> Option<TypeId> {
        let ty = self.parse_type_spec()?;
        self.types.reset_type(ty);
        loop {
            match self.peek() {
                Some(Token::InTran) => {
                    self.pos += 1;
                    self.expect(&Token::Colon);
                    let trans = self.expect_identifier()?;
                    let func = self.expect_identifier()?;
                    self.expect(&Token::LParen);
                    let stype = self.expect_identifier()?;
                    self.expect(&Token::RParen);
                    let it = &mut self.types[ty];
                    it.trans_type = Some(trans);
                    it.in_trans = Some(func);
                    it.server_type = Some(stype);
                }
                Some(Token::OutTran) => {
                    self.pos += 1;
                    self.expect(&Token::Colon);
                    let stype = self.expect_identifier()?;
                    let func = self.expect_identifier()?;
                    self.expect(&Token::LParen);
                    let trans = self.expect_identifier()?;
                    self.expect(&Token::RParen);
                    let it = &mut self.types[ty];
                    it.server_type = Some(stype);
                    it.out_trans = Some(func);
                    it.trans_type = Some(trans);
                }
                Some(Token::Destructor) => {
                    self.pos += 1;
                    self.expect(&Token::Colon);
                    let func = self.expect_identifier()?;
                    self.expect(&Token::LParen);
                    let trans = self.expect_identifier()?;
                    self.expect(&Token::RParen);
                    let it = &mut self.types[ty];
                    it.destructor = Some(func);
                    it.trans_type = Some(trans);
                }
                Some(Token::CType) => {
                    self.pos += 1;
                    self.expect(&Token::Colon);
                    let name = self.expect_identifier()?;
                    let it = &mut self.types[ty];
                    it.user_type = Some(name.clone());
                    it.server_type = Some(name);
                }
                Some(Token::CUserType) => {
                    self.pos += 1;
                    self.expect(&Token::Colon);
                    let name = self.expect_identifier()?;
                    self.types[ty].user_type = Some(name);
                }
                Some(Token::CServerType) => {
                    self.pos += 1;
                    self.expect(&Token::Colon);
                    let name = self.expect_identifier()?;
                    self.types[ty].server_type = Some(name);
                }
                _ => break,
            }
        }
        Some(ty)
    }

    /// `TypeSpec`
    fn parse_type_spec(&mut self) -> Option<TypeId> {
        match self.peek()? {
            Token::Array => self.parse_array_spec(),
            Token::Caret => {
                self.pos += 1;
                let inner = self.parse_type_spec()?;
                Some(self.types.ptr_decl(inner))
            }
            Token::Struct => self.parse_struct_spec(),
            Token::CString => self.parse_cstring_spec(),
            Token::PointerTo | Token::PointerToIfNot | Token::ValueOf => {
                self.parse_native_type_spec()
            }
            Token::LParen => {
                let sp = self.peek_span();
                self.diag
                    .error(sp, "Long form type declarations aren't allowed any longer");
                self.sync_to_semi();
                None
            }
            Token::Identifier(_) => {
                // PrevTypeSpec
                let sp = self.peek_span();
                let name = self.expect_identifier()?;
                if self.types.lookup(&name).is_none() {
                    self.diag.error(sp, &format!("type '{name}' not defined"));
                }
                Some(self.types.prev_decl(&name))
            }
            Token::SymbolicType { .. } | Token::Number(_) => self.parse_basic_type_spec(),
            _ => {
                let sp = self.peek_span();
                self.diag.error(sp, "expected type spec");
                None
            }
        }
    }

    /// `BasicTypeSpec: IPCType` → `itShortDecl`
    fn parse_basic_type_spec(&mut self) -> Option<TypeId> {
        let (inn, in_s, outn, out_s, size) = self.parse_ipc_type()?;
        Some(self.types.short_decl(inn, in_s, outn, out_s, size))
    }

    // Returns (in_num, in_str, out_num, out_str, size)
    fn parse_ipc_type(&mut self) -> Option<(u32, Option<String>, u32, Option<String>, u32)> {
        let (inn, in_s, outn, out_s, sz1) = self.parse_prim_ipc_type()?;
        if self.peek() == Some(&Token::Bar) {
            self.pos += 1;
            let (_, _, outn2, out_s2, sz2) = self.parse_prim_ipc_type()?;
            let size = match (sz1, sz2) {
                (0, s) | (s, 0) => s,
                (a, b) if a == b => a,
                _ => {
                    let sp = self.peek_span();
                    self.diag.error(sp, "sizes in IPCTypes don't match");
                    0
                }
            };
            Some((inn, in_s, outn2, out_s2, size))
        } else {
            Some((inn, in_s, outn, out_s, sz1))
        }
    }

    fn parse_prim_ipc_type(&mut self) -> Option<(u32, Option<String>, u32, Option<String>, u32)> {
        match self.peek()? {
            Token::Number(n) => {
                let n = *n;
                self.pos += 1;
                Some((n, None, n, None, 0))
            }
            Token::SymbolicType {
                in_number,
                in_str,
                out_number,
                out_str,
                size,
            } => {
                let v = (
                    *in_number,
                    Some(in_str.clone()),
                    *out_number,
                    Some(out_str.clone()),
                    *size,
                );
                self.pos += 1;
                Some(v)
            }
            _ => {
                let sp = self.peek_span();
                self.diag.error(sp, "expected IPC type");
                None
            }
        }
    }

    /// `VarArrayHead TypeSpec` / `ArrayHead TypeSpec`
    fn parse_array_spec(&mut self) -> Option<TypeId> {
        self.pos += 1; // consume `array`
        self.expect(&Token::LBrack);
        // variants: [], [*], [* : expr], [expr]
        let (varying, n) = if self.peek() == Some(&Token::RBrack) {
            self.pos += 1;
            self.expect(&Token::Of);
            (true, 0u32)
        } else if self.peek() == Some(&Token::Star) {
            self.pos += 1;
            if self.peek() == Some(&Token::RBrack) {
                self.pos += 1;
                self.expect(&Token::Of);
                (true, 0)
            } else {
                self.expect(&Token::Colon);
                let max = self.parse_int_expr()?;
                self.expect(&Token::RBrack);
                self.expect(&Token::Of);
                (true, max)
            }
        } else {
            let n = self.parse_int_expr()?;
            self.expect(&Token::RBrack);
            self.expect(&Token::Of);
            (false, n)
        };
        let elem = self.parse_type_spec()?;
        Some(if varying {
            self.types.var_array_decl(n, elem)
        } else {
            self.types.array_decl(n, elem)
        })
    }

    /// `StructHead TypeSpec`
    fn parse_struct_spec(&mut self) -> Option<TypeId> {
        self.pos += 1; // consume `struct`
        self.expect(&Token::LBrack);
        let n = self.parse_int_expr()?;
        self.expect(&Token::RBrack);
        self.expect(&Token::Of);
        let elem = self.parse_type_spec()?;
        Some(self.types.struct_decl(n, elem))
    }

    /// `CStringSpec`
    fn parse_cstring_spec(&mut self) -> Option<TypeId> {
        self.pos += 1; // consume `c_string`
        self.expect(&Token::LBrack);
        let varying = if self.peek() == Some(&Token::Star) {
            self.pos += 1;
            self.expect(&Token::Colon);
            true
        } else {
            false
        };
        let count = self.parse_int_expr()?;
        self.expect(&Token::RBrack);
        Some(self.types.cstring_decl(count, varying))
    }

    /// `NativeTypeSpec`
    fn parse_native_type_spec(&mut self) -> Option<TypeId> {
        let variant = self.peek()?.clone();
        self.pos += 1;
        self.expect(&Token::LParen);
        let c_type = self.parse_type_phrase()?;
        let (ptr, badval) = match variant {
            Token::PointerTo => (true, None),
            Token::PointerToIfNot => {
                self.expect(&Token::Comma);
                (true, Some(self.parse_type_phrase()?))
            }
            Token::ValueOf => (false, None),
            _ => unreachable!(),
        };
        self.expect(&Token::RParen);
        Some(self.types.native_type(c_type, ptr, badval))
    }

    fn parse_type_phrase(&mut self) -> Option<String> {
        let mut parts = vec![self.expect_identifier()?];
        while let Some(Token::Identifier(_)) = self.peek() {
            parts.push(self.expect_identifier()?);
        }
        Some(parts.join(" "))
    }

    // -----------------------------------------------------------------------
    // Integer expression (supports + - * /)
    // -----------------------------------------------------------------------

    fn parse_int_expr(&mut self) -> Option<u32> {
        self.parse_additive()
    }

    fn parse_additive(&mut self) -> Option<u32> {
        let mut lhs = self.parse_multiplicative()?;
        loop {
            match self.peek() {
                Some(Token::Plus) => {
                    self.pos += 1;
                    lhs += self.parse_multiplicative()?;
                }
                Some(Token::Minus) => {
                    self.pos += 1;
                    lhs -= self.parse_multiplicative()?;
                }
                _ => break,
            }
        }
        Some(lhs)
    }

    fn parse_multiplicative(&mut self) -> Option<u32> {
        let mut lhs = self.parse_primary_int()?;
        loop {
            match self.peek() {
                Some(Token::Star) => {
                    self.pos += 1;
                    lhs *= self.parse_primary_int()?;
                }
                Some(Token::Div) => {
                    self.pos += 1;
                    lhs /= self.parse_primary_int()?;
                }
                _ => break,
            }
        }
        Some(lhs)
    }

    fn parse_primary_int(&mut self) -> Option<u32> {
        match self.peek()? {
            Token::Number(n) => {
                let n = *n;
                self.pos += 1;
                Some(n)
            }
            Token::LParen => {
                self.pos += 1;
                let v = self.parse_int_expr()?;
                self.expect(&Token::RParen);
                Some(v)
            }
            _ => {
                let sp = self.peek_span();
                self.diag.error(sp, "expected integer expression");
                None
            }
        }
    }
}
