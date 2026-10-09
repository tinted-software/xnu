// SPDX-License-Identifier: MIT
// MIG type system — a port of migcom.tproj/type.c (ipc_type_t and friends).
//
// Types live in an arena (`Types`) and are referred to by `TypeId`, mirroring
// the shared `ipc_type_t *` pointers of the original: an argument declared
// `: foo_t` refers to the very same type object as the symbol table, and
// derived types (`array[...] of foo_t`, `type bar_t = foo_t`) keep a link to
// the type they were built from in `element`.

use std::collections::HashMap;

/// IPC wire type numbers (subset carried by the MIG grammar)
pub mod ipc_type_num {
    pub const MACH_MSG_TYPE_UNSTRUCTURED: u32 = 0;
    pub const MACH_MSG_TYPE_BIT: u32 = 0;
    pub const MACH_MSG_TYPE_BOOLEAN: u32 = 0;
    pub const MACH_MSG_TYPE_INTEGER_8: u32 = 9;
    pub const MACH_MSG_TYPE_INTEGER_16: u32 = 1;
    pub const MACH_MSG_TYPE_INTEGER_32: u32 = 2;
    pub const MACH_MSG_TYPE_INTEGER_64: u32 = 3;
    pub const MACH_MSG_TYPE_CHAR: u32 = 8;
    pub const MACH_MSG_TYPE_BYTE: u32 = 9;
    pub const MACH_MSG_TYPE_REAL_32: u32 = 10;
    pub const MACH_MSG_TYPE_REAL_64: u32 = 11;
    pub const MACH_MSG_TYPE_STRING_C: u32 = 12;

    // Port rights (osfmk/mach/message.h)
    pub const MACH_MSG_TYPE_PORT_NAME: u32 = 15;
    pub const MACH_MSG_TYPE_MOVE_RECEIVE: u32 = 16;
    pub const MACH_MSG_TYPE_MOVE_SEND: u32 = 17;
    pub const MACH_MSG_TYPE_MOVE_SEND_ONCE: u32 = 18;
    pub const MACH_MSG_TYPE_COPY_SEND: u32 = 19;
    pub const MACH_MSG_TYPE_MAKE_SEND: u32 = 20;
    pub const MACH_MSG_TYPE_MAKE_SEND_ONCE: u32 = 21;
    pub const MACH_MSG_TYPE_PORT_RECEIVE: u32 = MACH_MSG_TYPE_MOVE_RECEIVE;
    pub const MACH_MSG_TYPE_PORT_SEND: u32 = MACH_MSG_TYPE_MOVE_SEND;
    pub const MACH_MSG_TYPE_PORT_SEND_ONCE: u32 = MACH_MSG_TYPE_MOVE_SEND_ONCE;
    /// `((mach_msg_type_name_t) -1)`
    pub const MACH_MSG_TYPE_POLYMORPHIC: u32 = u32::MAX;

    /// `sizeof (mach_port_t) * NBBY` as seen by migcom (natural_t names).
    pub const PORT_SIZE: u32 = 32;

    /// `MACH_MSG_TYPE_PORT_ANY(x)`
    pub fn port_any(x: u32) -> bool {
        (MACH_MSG_TYPE_MOVE_RECEIVE..=MACH_MSG_TYPE_MAKE_SEND_ONCE).contains(&x)
    }
}

use ipc_type_num::*;

/// `ipc_flags_t` — per-argument IPC flags.
pub mod fl {
    pub const NONE: u32 = 0x000;
    pub const PHYSICAL_COPY: u32 = 0x001;
    pub const OVERWRITE: u32 = 0x002;
    pub const DEALLOC: u32 = 0x004;
    pub const NOT_DEALLOC: u32 = 0x008;
    pub const MAYBE_DEALLOC: u32 = 0x010;
    pub const SAME_COUNT: u32 = 0x020;
    pub const COUNT_IN_OUT: u32 = 0x040;
    pub const RET_CODE: u32 = 0x080;
    pub const AUTO: u32 = 0x100;
    pub const CONST: u32 = 0x200;
}

/// `natural_t` word size migcom aligns to (`itWordAlign`).
pub const WORD_ALIGN: u32 = 4;
/// `sizeof(natural_t) * NBBY`
pub const MACHINE_INTEGER_BITS: u32 = 32;
pub const MACHINE_INTEGER_NAME: &str = "MACH_MSG_TYPE_INTEGER_32";
pub const MACHINE_INTEGER_SIZE: u32 = MACH_MSG_TYPE_INTEGER_32;

/// `machine_padding(BYTES)`
pub fn machine_padding(bytes: u32) -> u32 {
    if bytes & 3 != 0 {
        4 - (bytes & 3)
    } else {
        0
    }
}

pub type TypeId = usize;

/// `ipc_type_t`
#[derive(Clone, Debug)]
pub struct IpcType {
    pub name: Option<String>,

    pub type_size: u32,
    pub pad_size: u32,
    pub min_type_size: u32,

    pub in_name: u32,
    pub out_name: u32,
    pub size: u32,
    pub number: u32,
    pub kpd_number: u32,
    pub in_line: bool,
    pub mig_in_line: bool,
    pub port_type: bool,

    pub in_name_str: Option<String>,
    pub out_name_str: Option<String>,

    pub is_struct: bool,
    pub is_string: bool,
    pub var_array: bool,
    pub no_opt_array: bool,
    pub native: bool,
    pub native_pointer: bool,

    pub element: Option<TypeId>,

    pub user_type: Option<String>,
    pub server_type: Option<String>,
    pub trans_type: Option<String>,

    pub kpd_type: Option<String>,

    pub in_trans: Option<String>,
    pub out_trans: Option<String>,
    pub destructor: Option<String>,
    pub bad_value: Option<String>,
    pub ool_number: u32,
}

impl IpcType {
    /// `itAlloc()` prototype.
    fn alloc() -> Self {
        IpcType {
            name: None,
            type_size: 0,
            pad_size: 0,
            min_type_size: 0,
            in_name: 0,
            out_name: 0,
            size: 0,
            number: 1,
            kpd_number: 0,
            in_line: true,
            mig_in_line: false,
            port_type: false,
            in_name_str: None,
            out_name_str: None,
            is_struct: true,
            is_string: false,
            var_array: false,
            no_opt_array: false,
            native: false,
            native_pointer: false,
            element: None,
            user_type: None,
            server_type: None,
            trans_type: None,
            kpd_type: None,
            in_trans: None,
            out_trans: None,
            destructor: None,
            bad_value: None,
            ool_number: 0,
        }
    }

    /// `IS_VARIABLE_SIZED_UNTYPED(x)`
    pub fn is_variable_sized_untyped(&self) -> bool {
        self.var_array && self.in_line && !self.port_type
    }

    /// `IS_KERN_PROC_DATA(x)`
    pub fn is_kern_proc_data(&self) -> bool {
        !self.in_line || self.port_type
    }

    /// `IS_OPTIONAL_NATIVE(x)`
    pub fn is_optional_native(&self) -> bool {
        self.native && self.native_pointer && self.bad_value.is_some()
    }

    /// `IS_MULTIPLE_KPD(x)`
    pub fn is_multiple_kpd(&self) -> bool {
        self.kpd_number > 1
    }

    /// `IS_MIG_INLINE_EMUL(x)`
    pub fn is_mig_inline_emul(&self) -> bool {
        self.mig_in_line
    }

    pub fn user_type(&self) -> &str {
        self.user_type.as_deref().unwrap_or("")
    }

    pub fn server_type(&self) -> &str {
        self.server_type.as_deref().unwrap_or("")
    }

    pub fn trans_type(&self) -> &str {
        self.trans_type.as_deref().unwrap_or("")
    }

    pub fn kpd_type(&self) -> &str {
        self.kpd_type.as_deref().unwrap_or("")
    }

    pub fn in_name_str(&self) -> &str {
        self.in_name_str.as_deref().unwrap_or("")
    }

    pub fn out_name_str(&self) -> &str {
        self.out_name_str.as_deref().unwrap_or("")
    }
}

/// The type arena plus the named-type symbol table and MIG's built-in types.
pub struct Types {
    arena: Vec<IpcType>,
    table: HashMap<String, TypeId>,
    pub ret_code: TypeId,
    pub ndr_code: TypeId,
    pub zero_reply_port: TypeId,
    pub real_reply_port: TypeId,
    pub wait_time: TypeId,
    pub msg_option: TypeId,
    /// Warnings raised while building types (`warn()` in type.c).
    pub warnings: Vec<String>,
    /// Errors raised while building types (`error()` in type.c).
    pub errors: Vec<String>,
}

impl std::ops::Index<TypeId> for Types {
    type Output = IpcType;
    fn index(&self, id: TypeId) -> &IpcType {
        &self.arena[id]
    }
}

impl std::ops::IndexMut<TypeId> for Types {
    fn index_mut(&mut self, id: TypeId) -> &mut IpcType {
        &mut self.arena[id]
    }
}

impl Default for Types {
    fn default() -> Self {
        Self::new()
    }
}

impl Types {
    /// `init_type()`
    pub fn new() -> Self {
        let mut t = Types {
            arena: Vec::new(),
            table: HashMap::new(),
            ret_code: 0,
            ndr_code: 0,
            zero_reply_port: 0,
            real_reply_port: 0,
            wait_time: 0,
            msg_option: 0,
            warnings: Vec::new(),
            errors: Vec::new(),
        };
        let int = |name: &str| {
            let mut it = IpcType::alloc();
            it.name = Some(name.into());
            it.in_name = MACHINE_INTEGER_SIZE;
            it.in_name_str = Some(MACHINE_INTEGER_NAME.into());
            it.out_name = MACHINE_INTEGER_SIZE;
            it.out_name_str = Some(MACHINE_INTEGER_NAME.into());
            it.size = MACHINE_INTEGER_BITS;
            it
        };
        t.ret_code = t.push_finished(int("kern_return_t"));

        let mut ndr = IpcType::alloc();
        ndr.name = Some("NDR_record_t".into());
        ndr.in_name_str = Some("NDR_record_t".into());
        ndr.out_name_str = Some("NDR_record_t".into());
        ndr.size = 8 * 8;
        t.ndr_code = t.push_finished(ndr);

        let port = |inn: u32, ins: &str, out: u32, outs: &str| {
            let mut it = IpcType::alloc();
            it.name = Some("mach_port_t".into());
            it.in_name = inn;
            it.in_name_str = Some(ins.into());
            it.out_name = out;
            it.out_name_str = Some(outs.into());
            it.size = PORT_SIZE;
            it
        };
        t.zero_reply_port = t.push_finished(port(0, "0", 0, "0"));
        t.real_reply_port = t.push_finished(port(
            MACH_MSG_TYPE_MAKE_SEND_ONCE,
            "MACH_MSG_TYPE_MAKE_SEND_ONCE",
            MACH_MSG_TYPE_PORT_SEND_ONCE,
            "MACH_MSG_TYPE_PORT_SEND_ONCE",
        ));
        t.wait_time = t.make_count_type();
        t.msg_option = t.make_count_type();
        t
    }

    fn push(&mut self, it: IpcType) -> TypeId {
        self.arena.push(it);
        self.arena.len() - 1
    }

    /// Push a type and run `itCalculateSizeInfo` + `itCalculateNameInfo`.
    fn push_finished(&mut self, it: IpcType) -> TypeId {
        let id = self.push(it);
        self.calculate_size_info(id);
        self.calculate_name_info(id);
        id
    }

    fn warn(&mut self, msg: String) {
        self.warnings.push(msg);
    }

    fn error(&mut self, msg: String) {
        self.errors.push(msg);
    }

    /// `itLookUp`
    pub fn lookup(&self, name: &str) -> Option<TypeId> {
        self.table.get(name).copied()
    }

    /// `itInsert`
    pub fn insert(&mut self, name: &str, id: TypeId) {
        if self.table.contains_key(name) {
            self.warn(format!("overriding previous definition of {name}"));
        }
        self.arena[id].name = Some(name.into());
        self.table.insert(name.into(), id);
    }

    /// `itCalculateSizeInfo`
    fn calculate_size_info(&mut self, id: TypeId) {
        let it = &mut self.arena[id];
        if !it.is_kern_proc_data() {
            let bytes = (it.number * it.size + 7) / 8;
            let padding = machine_padding(bytes);
            it.type_size = bytes;
            it.pad_size = padding;
            if it.is_variable_sized_untyped() {
                // The count is not an akbRequest|akbReply argument for these
                // arrays; its space is accounted for here.
                it.min_type_size = 4;
                // NDR-encoded var strings carry an extra (unused) offset.
                if it.is_string {
                    it.min_type_size += 4;
                }
            } else {
                it.min_type_size = bytes + padding;
            }
        } else {
            // ports, OOL and OOL ports all count as sizeof(mach_msg_descriptor_t)
            let bytes = if it.is_multiple_kpd() {
                it.kpd_number * 12
            } else {
                12
            };
            it.type_size = bytes;
            it.pad_size = 0;
            it.min_type_size = bytes;
        }
    }

    /// `itCalculateNameInfo`
    fn calculate_name_info(&mut self, id: TypeId) {
        let it = &mut self.arena[id];
        if it.in_name_str.is_none() {
            it.in_name_str = Some(it.in_name.to_string());
        }
        if it.out_name_str.is_none() {
            it.out_name_str = Some(it.out_name.to_string());
        }
        if it.user_type.is_none() {
            it.user_type = it.name.clone();
        }
        if it.server_type.is_none() {
            it.server_type = it.name.clone();
        }
        if it.trans_type.is_none() {
            it.trans_type = it.server_type.clone();
        }
    }

    /// `itCheckDecl` / `itTypeDecl`: name a type and fill in its C spellings.
    pub fn type_decl(&mut self, name: &str, id: TypeId) {
        self.arena[id].name = Some(name.into());
        self.calculate_name_info(id);
        let it = &self.arena[id];
        let (var, trans, destr) = (
            it.var_array,
            it.in_trans.is_some() || it.out_trans.is_some(),
            it.destructor.is_some(),
        );
        if var && trans {
            self.error(format!("{name}: can't translate variable-sized arrays"));
        }
        if var && destr {
            self.error(format!("{name}: can't destroy variable-sized array"));
        }
    }

    /// `itShortDecl`
    pub fn short_decl(
        &mut self,
        inname: u32,
        instr: Option<String>,
        outname: u32,
        outstr: Option<String>,
        defsize: u32,
    ) -> TypeId {
        if defsize == 0 {
            self.error("must use full IPC type decl".into());
        }
        let mut it = IpcType::alloc();
        it.in_name = inname;
        it.in_name_str = instr;
        it.out_name = outname;
        it.out_name_str = outstr;
        it.size = defsize;
        if inname == MACH_MSG_TYPE_STRING_C {
            it.is_struct = false;
            it.is_string = true;
        }
        if port_any(inname) || inname == MACH_MSG_TYPE_POLYMORPHIC {
            it.port_type = true;
            it.kpd_number = 1;
        }
        let id = self.push(it);
        self.calculate_size_info(id);
        id
    }

    /// `itCopyType`
    fn copy_type(&mut self, old: TypeId) -> TypeId {
        let mut new = self.arena[old].clone();
        new.name = None;
        new.element = Some(old);
        self.push(new)
    }

    /// `itResetType`
    pub fn reset_type(&mut self, id: TypeId) -> TypeId {
        let it = &mut self.arena[id];
        it.in_trans = None;
        it.out_trans = None;
        it.destructor = None;
        it.user_type = None;
        it.server_type = None;
        it.trans_type = None;
        id
    }

    /// `itPrevDecl`
    pub fn prev_decl(&mut self, name: &str) -> TypeId {
        match self.lookup(name) {
            Some(old) => self.copy_type(old),
            None => {
                self.error(format!("type '{name}' not defined"));
                self.push(IpcType::alloc())
            }
        }
    }

    /// `itVarArrayDecl`
    pub fn var_array_decl(&mut self, number: u32, old: TypeId) -> TypeId {
        let id = self.copy_type(old);
        self.reset_type(id);
        let it = &self.arena[id];
        if !it.in_line {
            // already an initialized KPD
            if it.kpd_number != 1 || number == 0 {
                self.error("IPC type decl is too complicated for Kernel Processed Data".into());
            }
            let it = &mut self.arena[id];
            it.kpd_number *= number;
            it.number = 1;
            it.in_line = false;
            it.is_struct = false;
            it.ool_number = number;
        } else if it.var_array {
            self.error("IPC type decl is too complicated".into());
        } else if number != 0 {
            // Bounded [Scalar, Port] VarArray: in-line
            let it = &mut self.arena[id];
            it.number *= number;
            it.in_line = true;
            it.is_struct = false;
            if it.port_type {
                it.kpd_number *= number;
            }
            it.ool_number = number;
        } else {
            // Unbounded [Scalar, Port] VarArray: in-line interface,
            // out-of-line mechanism.
            let it = &mut self.arena[id];
            it.number = 0;
            it.mig_in_line = true;
            it.in_line = false;
            it.is_struct = true;
            it.kpd_number = 1;
            it.ool_number = 0;
        }
        let it = &mut self.arena[id];
        it.var_array = true;
        it.is_string = false;
        self.calculate_size_info(id);
        id
    }

    /// `itArrayDecl`
    pub fn array_decl(&mut self, number: u32, old: TypeId) -> TypeId {
        let id = self.copy_type(old);
        self.reset_type(id);
        let it = &self.arena[id];
        if !it.in_line {
            if it.kpd_number != 1 {
                self.error("IPC type decl is too complicated for Kernel Processed Data".into());
            }
            let it = &mut self.arena[id];
            it.kpd_number *= number;
            it.number = 1;
            it.is_struct = false;
            it.is_string = false;
            it.var_array = false;
        } else if it.var_array {
            self.error("IPC type decl is too complicated".into());
        } else {
            let it = &mut self.arena[id];
            it.number *= number;
            it.is_struct = false;
            it.is_string = false;
            if it.port_type {
                it.kpd_number *= number;
            }
        }
        self.calculate_size_info(id);
        id
    }

    /// `itPtrDecl` (mutates its operand, like the original)
    pub fn ptr_decl(&mut self, id: TypeId) -> TypeId {
        let it = &self.arena[id];
        if !it.in_line && !it.mig_in_line {
            self.error("IPC type decl is already defined to be Out-Of-Line".into());
        }
        let it = &mut self.arena[id];
        it.in_line = false;
        it.is_struct = true;
        it.is_string = false;
        it.mig_in_line = false;
        it.kpd_number = 1;
        self.calculate_size_info(id);
        id
    }

    /// `itStructDecl`
    pub fn struct_decl(&mut self, number: u32, old: TypeId) -> TypeId {
        let id = self.copy_type(old);
        self.reset_type(id);
        let it = &self.arena[id];
        if !it.in_line || it.var_array {
            self.error("IPC type decl is too complicated".into());
        }
        let it = &mut self.arena[id];
        it.number *= number;
        it.is_struct = true;
        it.is_string = false;
        self.calculate_size_info(id);
        id
    }

    /// `itCStringDecl`
    pub fn cstring_decl(&mut self, count: u32, varying: bool) -> TypeId {
        let elem = self.short_decl(
            MACH_MSG_TYPE_STRING_C,
            Some("MACH_MSG_TYPE_STRING_C".into()),
            MACH_MSG_TYPE_STRING_C,
            Some("MACH_MSG_TYPE_STRING_C".into()),
            8,
        );
        self.type_decl("char", elem);
        let id = self.copy_type(elem);
        self.reset_type(id);
        let it = &mut self.arena[id];
        it.number = count;
        it.var_array = varying;
        it.is_struct = false;
        it.is_string = true;
        self.calculate_size_info(id);
        id
    }

    /// `itMakeSubCountType`
    pub fn make_sub_count_type(&mut self, count: u32, varying: bool) -> TypeId {
        let elem = self.short_decl(
            MACHINE_INTEGER_SIZE,
            Some(MACHINE_INTEGER_NAME.into()),
            MACHINE_INTEGER_SIZE,
            Some(MACHINE_INTEGER_NAME.into()),
            MACHINE_INTEGER_BITS,
        );
        self.type_decl("mach_msg_type_number_t", elem);
        let id = self.copy_type(elem);
        self.reset_type(id);
        let it = &mut self.arena[id];
        it.number = count;
        // Not a fixed array, or MIG would take the optimized array copy path.
        it.var_array = false;
        it.is_struct = false;
        it.is_string = false;
        it.in_line = true;
        it.name = Some("mach_msg_type_number_t *".into());
        if varying {
            it.var_array = true;
        } else {
            it.no_opt_array = true;
        }
        self.calculate_size_info(id);
        self.calculate_name_info(id);
        id
    }

    fn make_int_type(&mut self, name: &str, inname: u32, instr: &str, size: u32) -> TypeId {
        let mut it = IpcType::alloc();
        it.name = Some(name.into());
        it.in_name = inname;
        it.in_name_str = Some(instr.into());
        it.out_name = inname;
        it.out_name_str = Some(instr.into());
        it.size = size;
        self.push_finished(it)
    }

    /// `itMakeCountType`
    pub fn make_count_type(&mut self) -> TypeId {
        self.make_int_type(
            "mach_msg_type_number_t",
            MACHINE_INTEGER_SIZE,
            MACHINE_INTEGER_NAME,
            MACHINE_INTEGER_BITS,
        )
    }

    /// `itMakePolyType`
    pub fn make_poly_type(&mut self) -> TypeId {
        self.make_int_type(
            "mach_msg_type_name_t",
            MACHINE_INTEGER_SIZE,
            MACHINE_INTEGER_NAME,
            MACHINE_INTEGER_BITS,
        )
    }

    /// `itMakeDeallocType`
    pub fn make_dealloc_type(&mut self) -> TypeId {
        self.make_int_type(
            "boolean_t",
            MACH_MSG_TYPE_BOOLEAN,
            "MACH_MSG_TYPE_BOOLEAN",
            MACHINE_INTEGER_BITS,
        )
    }

    /// `itNativeType`
    pub fn native_type(&mut self, ctype: String, ptr: bool, badval: Option<String>) -> TypeId {
        let mut it = IpcType::alloc();
        it.in_name = MACH_MSG_TYPE_BYTE;
        it.in_name_str = Some("MACH_MSG_TYPE_BYTE".into());
        it.out_name = MACH_MSG_TYPE_BYTE;
        it.out_name_str = Some("MACH_MSG_TYPE_BYTE".into());
        it.in_line = true;
        it.native = true;
        it.native_pointer = ptr;
        it.server_type = Some(ctype.clone());
        it.user_type = Some(ctype.clone());
        it.trans_type = Some(ctype);
        it.bad_value = badval;
        self.push_finished(it)
    }

    /// A placeholder type for an argument whose type failed to resolve.
    pub fn placeholder(&mut self) -> TypeId {
        self.push(IpcType::alloc())
    }

    /// `itCheckRequestPortType`
    pub fn check_request_port_type(&self, name: &str, id: TypeId) -> Result<(), String> {
        let it = &self.arena[id];
        if (it.out_name != MACH_MSG_TYPE_PORT_SEND
            && it.out_name != MACH_MSG_TYPE_PORT_SEND_ONCE
            && it.out_name != MACH_MSG_TYPE_POLYMORPHIC)
            || it.number != 1
            || it.size != PORT_SIZE
            || !it.in_line
            || !it.is_struct
            || it.var_array
        {
            return Err(format!("argument {name} isn't a proper request port"));
        }
        Ok(())
    }

    /// `itCheckReplyPortType`
    pub fn check_reply_port_type(&self, name: &str, id: TypeId) -> Result<(), String> {
        let it = &self.arena[id];
        if (it.out_name != MACH_MSG_TYPE_PORT_SEND
            && it.out_name != MACH_MSG_TYPE_PORT_SEND_ONCE
            && it.out_name != MACH_MSG_TYPE_POLYMORPHIC
            && it.out_name != 0)
            || it.number != 1
            || it.size != PORT_SIZE
            || !it.in_line
            || !it.is_struct
            || it.var_array
        {
            return Err(format!("argument {name} isn't a proper reply port"));
        }
        Ok(())
    }

    /// `itCheckIntType`
    pub fn check_int_type(&self, name: &str, id: TypeId) -> Result<(), String> {
        let it = &self.arena[id];
        if it.in_name != MACHINE_INTEGER_SIZE
            || it.out_name != MACHINE_INTEGER_SIZE
            || it.number != 1
            || it.size != MACHINE_INTEGER_BITS
            || !it.in_line
            || !it.is_struct
            || it.var_array
        {
            return Err(format!("argument {name} isn't a proper integer"));
        }
        Ok(())
    }
}
