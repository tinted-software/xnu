// SPDX-License-Identifier: MIT OR Apache-2.0
//! Global allocator for the kernel-resident Rust modules, backed by the
//! kernel's data heap (`kalloc_data_external` / `kfree_data_external`, the
//! same KPI that kexts use). Allocations may block (`Z_WAITOK`), so Rust code
//! that allocates must only run in thread context with preemption enabled.
//!
//! The kernel heap hands out 16-byte aligned blocks; larger alignments are
//! satisfied by over-allocating and stashing the original pointer directly
//! below the aligned block.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

/// `zalloc_flags_t` values from osfmk/kern/zalloc.h.
const Z_WAITOK: u32 = 0x0000;
const Z_ZERO: u32 = 0x0004;

/// Alignment the kernel heap guarantees for every block.
const KALLOC_ALIGN: usize = 16;

extern "C" {
    fn kalloc_data_external(size: usize, flags: u32) -> *mut u8;
    fn kfree_data_external(ptr: *mut u8, size: usize);
}

pub struct KernelAllocator;

impl KernelAllocator {
    /// Size of the underlying kernel block for an over-aligned request.
    #[inline]
    fn padded(layout: Layout) -> Option<usize> {
        layout.size().checked_add(layout.align())
    }

    #[inline]
    unsafe fn alloc_flags(layout: Layout, flags: u32) -> *mut u8 {
        if layout.align() <= KALLOC_ALIGN {
            return kalloc_data_external(layout.size(), flags);
        }
        let Some(total) = Self::padded(layout) else {
            return ptr::null_mut();
        };
        let raw = kalloc_data_external(total, flags);
        if raw.is_null() {
            return raw;
        }
        // Leave room for the back-pointer, then round up to the alignment.
        let aligned = (raw as usize + core::mem::size_of::<usize>() + layout.align() - 1)
            & !(layout.align() - 1);
        (aligned as *mut usize).sub(1).write(raw as usize);
        aligned as *mut u8
    }
}

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        Self::alloc_flags(layout, Z_WAITOK)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        Self::alloc_flags(layout, Z_WAITOK | Z_ZERO)
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        if layout.align() <= KALLOC_ALIGN {
            kfree_data_external(p, layout.size());
            return;
        }
        // `alloc_flags` verified the sum when the block was created.
        let total = layout.size() + layout.align();
        let raw = (p as *mut usize).sub(1).read() as *mut u8;
        kfree_data_external(raw, total);
    }
}

#[global_allocator]
static ALLOCATOR: KernelAllocator = KernelAllocator;
