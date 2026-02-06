#![no_std]
#![no_main]

//! Kprobe argument tracer for AxVisor.
//!
//! This eBPF program captures function arguments from pt_regs when
//! attached to a kprobe. It reads the first 4 arguments (x0-x3 on aarch64)
//! and stores them in a map for later retrieval.
//!
//! The program receives a pointer to pt_regs structure from the kprobe handler.

use aya_ebpf::{
    macros::{kprobe, map},
    maps::HashMap,
    programs::ProbeContext,
};

/// Maximum number of entries to track
const MAX_ENTRIES: u32 = 256;

/// Captured function arguments
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FuncArgs {
    /// Program counter (function address)
    pub pc: u64,
    /// Invocation count for this probe point
    pub count: u64,
    /// First argument (x0 on aarch64, rdi on x86_64)
    pub arg0: u64,
    /// Second argument (x1 on aarch64, rsi on x86_64)
    pub arg1: u64,
    /// Third argument (x2 on aarch64, rdx on x86_64)
    pub arg2: u64,
    /// Fourth argument (x3 on aarch64, rcx on x86_64)
    pub arg3: u64,
}

/// Map to store captured arguments, keyed by probe address (PC)
#[map]
static ARGS_MAP: HashMap<u64, FuncArgs> = HashMap::with_max_entries(MAX_ENTRIES, 0);

/// Kprobe entry point - captures function arguments from pt_regs.
///
/// The context pointer points to a pt_regs structure:
/// - AArch64: regs[0..31], sp, pc, pstate, orig_x0, syscallno
/// - x86_64: various registers including rdi, rsi, rdx, rcx, rip
#[kprobe]
pub fn kprobe_args(ctx: ProbeContext) -> u32 {
    match try_kprobe_args(ctx) {
        Ok(count) => count as u32,
        Err(_) => 0xFFFFFFFF,
    }
}

/// Internal implementation that can return errors.
fn try_kprobe_args(ctx: ProbeContext) -> Result<u64, i64> {
    // Read pt_regs fields based on architecture
    // AArch64 pt_regs layout:
    //   offset 0:   regs[0] (x0) - first argument
    //   offset 8:   regs[1] (x1) - second argument
    //   offset 16:  regs[2] (x2) - third argument
    //   offset 24:  regs[3] (x3) - fourth argument
    //   ...
    //   offset 248: regs[31] (sp)
    //   offset 256: pc

    #[cfg(target_arch = "aarch64")]
    let (pc, arg0, arg1, arg2, arg3) = unsafe {
        let pc: u64 = ctx.read_at(256)?;      // offset of pc in pt_regs
        let arg0: u64 = ctx.read_at(0)?;      // x0
        let arg1: u64 = ctx.read_at(8)?;      // x1
        let arg2: u64 = ctx.read_at(16)?;     // x2
        let arg3: u64 = ctx.read_at(24)?;     // x3
        (pc, arg0, arg1, arg2, arg3)
    };

    // x86_64 pt_regs layout (simplified, actual layout may vary):
    //   rdi, rsi, rdx, rcx are the first 4 arguments
    #[cfg(target_arch = "x86_64")]
    let (pc, arg0, arg1, arg2, arg3) = unsafe {
        // These offsets are based on Linux pt_regs structure
        let pc: u64 = ctx.read_at(128)?;      // rip offset (varies by kernel)
        let arg0: u64 = ctx.read_at(112)?;    // rdi
        let arg1: u64 = ctx.read_at(104)?;    // rsi
        let arg2: u64 = ctx.read_at(96)?;     // rdx
        let arg3: u64 = ctx.read_at(88)?;     // rcx
        (pc, arg0, arg1, arg2, arg3)
    };

    // For other architectures, use placeholder values
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    let (pc, arg0, arg1, arg2, arg3) = (0u64, 0u64, 0u64, 0u64, 0u64);

    // Get existing entry or create new one
    let mut args = unsafe {
        ARGS_MAP.get(&pc).copied().unwrap_or(FuncArgs {
            pc,
            count: 0,
            arg0: 0,
            arg1: 0,
            arg2: 0,
            arg3: 0,
        })
    };

    // Update with current invocation data
    args.count += 1;
    args.arg0 = arg0;
    args.arg1 = arg1;
    args.arg2 = arg2;
    args.arg3 = arg3;

    // Store in map
    unsafe {
        ARGS_MAP.insert(&pc, &args, 0)?;
    }

    // Return the count for logging by the hypervisor
    Ok(args.count)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
