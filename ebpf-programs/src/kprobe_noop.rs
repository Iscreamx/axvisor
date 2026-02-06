#![no_std]
#![no_main]

//! Minimal kprobe for testing - does nothing, just returns 1.
//!
//! This is the simplest possible eBPF program to test if kprobe execution works.

use aya_ebpf::{
    macros::kprobe,
    programs::ProbeContext,
};

/// Minimal kprobe - just returns 1, no helper calls at all.
#[kprobe]
pub fn kprobe_noop(_ctx: ProbeContext) -> u32 {
    1
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
