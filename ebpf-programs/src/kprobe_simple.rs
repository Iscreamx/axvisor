#![no_std]
#![no_main]

//! Simple kprobe tracer for AxVisor.
//!
//! A minimal eBPF program that captures only the first argument (x0 on aarch64)
//! to avoid exceeding the nested call limit.

use aya_ebpf::{
    macros::{kprobe, map},
    maps::HashMap,
    programs::ProbeContext,
};

/// Captured data: just PC and first argument
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SimpleArgs {
    /// Program counter (function address)
    pub pc: u64,
    /// Invocation count
    pub count: u64,
    /// First argument (x0 on aarch64)
    pub arg0: u64,
}

/// Map to store captured data, keyed by probe address
#[map]
static SIMPLE_MAP: HashMap<u64, SimpleArgs> = HashMap::with_max_entries(64, 0);

/// Simple kprobe - only captures first argument to minimize helper calls.
#[kprobe]
pub fn kprobe_simple(ctx: ProbeContext) -> u32 {
    match try_kprobe_simple(ctx) {
        Ok(count) => count as u32,
        Err(code) => code as u32,
    }
}

fn try_kprobe_simple(ctx: ProbeContext) -> Result<u64, i64> {
    // Read registers based on architecture
    #[cfg(target_arch = "aarch64")]
    let (pc, arg0) = unsafe {
        let arg0: u64 = ctx.read_at(0)?;      // x0 at offset 0
        let pc: u64 = ctx.read_at(256)?;      // pc at offset 256
        (pc, arg0)
    };

    #[cfg(target_arch = "x86_64")]
    let (pc, arg0) = unsafe {
        let arg0: u64 = ctx.read_at(112)?;    // rdi
        let pc: u64 = ctx.read_at(128)?;      // rip
        (pc, arg0)
    };

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    let (pc, arg0) = (0u64, 0u64);

    // Get existing entry or create new
    let mut data = unsafe {
        SIMPLE_MAP.get(&pc).copied().unwrap_or(SimpleArgs {
            pc,
            count: 0,
            arg0: 0,
        })
    };

    // Update
    data.count += 1;
    data.arg0 = arg0;

    // Store
    unsafe { SIMPLE_MAP.insert(&pc, &data, 0)? };

    Ok(data.count)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
