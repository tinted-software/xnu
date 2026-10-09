use crate::main_defs::*;

pub struct AfdtWriter {
    pub cur: u64,
}

impl AfdtWriter {
    pub fn new(addr: u64) -> Self {
        Self { cur: addr }
    }

    pub unsafe fn write_u32(&mut self, val: u32) {
        let p = self.cur as *mut u32;
        core::ptr::write_unaligned(p, val.to_le());
        self.cur += 4;
    }

    pub unsafe fn write_u64(&mut self, val: u64) {
        let p = self.cur as *mut u64;
        core::ptr::write_unaligned(p, val.to_le());
        self.cur += 8;
    }

    pub unsafe fn write_bytes(&mut self, b: &[u8]) {
        let mut p = self.cur as *mut u8;
        for &byte in b {
            *p = byte;
            p = p.add(1);
        }
        self.cur += b.len() as u64;
    }

    pub unsafe fn write_zeros(&mut self, n: u64) {
        let mut p = self.cur as *mut u8;
        for _ in 0..n {
            *p = 0;
            p = p.add(1);
        }
        self.cur += n;
    }

    pub unsafe fn node(&mut self, prop_count: u32, child_count: u32) {
        self.write_u32(prop_count);
        self.write_u32(child_count);
    }

    pub unsafe fn prop_name(&mut self, name: &str) {
        let b = name.as_bytes();
        self.write_bytes(b);
        if b.len() < 32 {
            self.write_zeros((32 - b.len()) as u64);
        }
    }

    pub unsafe fn string_prop(&mut self, name: &str, value: &str) {
        self.prop_name(name);
        let raw_len = (value.len() + 1) as u32;
        let padded = (raw_len + 3) & !3;
        self.write_u32(raw_len);
        self.write_bytes(value.as_bytes());
        self.write_zeros((padded - value.len() as u32) as u64);
    }

    pub unsafe fn pair_prop(&mut self, name: &str, a: u64, b: u64) {
        self.prop_name(name);
        self.write_u32(16);
        self.write_u64(a);
        self.write_u64(b);
    }

    pub unsafe fn u32_prop(&mut self, name: &str, val: u32) {
        self.prop_name(name);
        self.write_u32(4);
        self.write_u32(val);
    }

    pub unsafe fn u64_prop(&mut self, name: &str, val: u64) {
        self.prop_name(name);
        self.write_u32(8);
        self.write_u64(val);
    }

    pub unsafe fn bytes_prop(&mut self, name: &str, val: &[u8]) {
        self.prop_name(name);
        let padded = ((val.len() + 3) & !3) as u64;
        self.write_u32(padded as u32);
        self.write_bytes(val);
        self.write_zeros(padded - val.len() as u64);
    }
}

pub unsafe fn build_afdt(
    addr: u64,
    ram_base: u64,
    // Full size of the physical DRAM bank, *including* any regions carved out
    // of it (such as the panic log). This becomes chosen/dram-size, which the
    // kernel turns into gDramSize and uses for is_dram_addr(). It is NOT the
    // amount of memory available to the kernel allocator -- that is
    // boot_args.mem_size, which excludes the reserved regions.
    dram_size: u64,
    panic_log_phys: u64,
    panic_log_size: u32,
    ramdisk_phys: u64,
    ramdisk_size: u64,
    // (paddr, length) of the trust cache window, or None when no blob is loaded.
    trust_cache: Option<(u64, u64)>,
    cmdline: &str,
) -> u32 {
    let mut w = AfdtWriter::new(addr);

    // Root node: 3 properties ("name", "compatible", "model"), 5 children ("chosen", "defaults", "arm-io", "cpus", "pram")
    //
    // `compatible` is what hw.target reports (IODTPlatformExpert::getTargetName)
    // and `model` is hw.product. A neutral QEMU identity: userspace that needs a
    // real device target must be mapped case by case.
    w.node(3, 5);
    w.string_prop("name", "device-tree");
    w.string_prop("compatible", "QEMU,virt");
    w.string_prop("model", "QEMU1,1");

    // "chosen": 11 properties, 1 child ("memory-map")
    w.node(11, 1);
    w.string_prop("name", "chosen");
    w.u64_prop("dram-base", ram_base);
    w.u64_prop("dram-size", dram_size);
    w.string_prop("firmware-version", "qemu-boot-99.0.0");
    w.string_prop("system-firmware-version", "qemu-boot-99.0.0");
    w.string_prop("boot-args", cmdline);
    w.bytes_prop("unique-chip-id", &[1, 2, 3, 4, 5, 6, 7, 8]);
    w.u32_prop("embedded-panic-log-size", panic_log_size);
    w.u32_prop("kernel-ctrr-to-be-enabled", 0);
    // No persistent data volume: hw.ephemeral_storage. keybagd, among others,
    // skips keybag initialization on an ephemeral-storage device.
    w.u32_prop("ephemeral-storage", 1);

    // random-seed property (256 bytes)
    w.prop_name("random-seed");
    w.write_u32(256);
    let mut p = w.cur as *mut u8;
    for i in 0..256 {
        *p = (i * 0x9d + 0x5a) as u8;
        p = p.add(1);
    }
    w.cur += 256;

    // "chosen/memory-map": "name", "RAMDisk", and optionally "TrustCache" (DTTrustCacheRange)
    let memory_map_props = if trust_cache.is_some() { 3 } else { 2 };
    w.node(memory_map_props, 0);
    w.string_prop("name", "memory-map");
    w.pair_prop("RAMDisk", ramdisk_phys, ramdisk_size);
    if let Some((tc_phys, tc_len)) = trust_cache {
        w.pair_prop("TrustCache", tc_phys, tc_len);
    }

    // "defaults": 2 properties, 0 children
    w.node(2, 0);
    w.string_prop("name", "defaults");
    w.u32_prop("serial-device", 0x100);

    // "arm-io": 3 properties, 3 children ("uart0", "gic", "timer")
    w.node(3, 3);
    w.string_prop("name", "arm-io");
    w.string_prop("device_type", "arm-io");
    w.pair_prop("ranges", 0, GICD_BASE);

    // "arm-io/uart0" (PL011)
    w.node(4, 0);
    w.string_prop("name", "uart0");
    w.string_prop("compatible", "arm,pl011");
    w.pair_prop("reg", PL011_BASE as u64 - GICD_BASE, 0x1000);
    w.u32_prop("AAPL,phandle", 0x100);

    // "arm-io/gic" (GICv2)
    w.node(4, 0);
    w.string_prop("name", "gic");
    w.string_prop("interrupt-controller", "master");
    w.string_prop("compatible", "arm,gic-400");
    w.pair_prop("reg", 0, 0x1000);

    // "arm-io/timer" (PL031 dummy MMIO)
    w.node(3, 0);
    w.string_prop("name", "timer");
    w.string_prop("device_type", "timer");
    w.pair_prop("reg", PL031_BASE - GICD_BASE, 0x1000);

    // "cpus": 1 property, 1 child ("cpu0")
    w.node(1, 1);
    w.string_prop("name", "cpus");

    // "cpus/cpu0"
    w.node(5, 0);
    w.string_prop("name", "cpu0");
    w.string_prop("state", "running");
    w.u32_prop("reg", 0);
    w.u32_prop("timebase-frequency", 62500000);
    w.u32_prop("clock-frequency", 1000000000);

    // "pram"
    w.node(2, 0);
    w.string_prop("name", "pram");
    w.pair_prop("reg", panic_log_phys, panic_log_size as u64);

    (w.cur - addr) as u32
}
