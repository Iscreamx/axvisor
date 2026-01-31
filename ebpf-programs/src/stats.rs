#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};

/// Statistics value structure for each tracepoint
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StatsValue {
    /// Invocation count
    pub count: u64,
    /// Total duration in nanoseconds
    pub total_ns: u64,
    /// Minimum duration in nanoseconds
    pub min_ns: u64,
    /// Maximum duration in nanoseconds
    pub max_ns: u64,
}

/// Stats Map: tracepoint_id -> StatsValue
#[map]
static STATS_MAP: HashMap<u32, StatsValue> = HashMap::with_max_entries(128, 0);

/// Entry point - collects COUNT/TOTAL/MIN/MAX statistics
#[tracepoint]
pub fn stats(ctx: TracePointContext) -> u32 {
    match try_stats(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_stats(ctx: TracePointContext) -> Result<(), i64> {
    // TraceContext layout:
    // offset 0: tracepoint_id (u32)
    // offset 4: padding
    // offset 8: timestamp_ns (u64)
    // offset 16: vm_id (u32)
    // offset 20: vcpu_id (u32)
    // offset 24: arg0 (u64) - duration_ns for timed events

    let tp_id: u32 = unsafe { ctx.read_at(0)? };
    let duration_ns: u64 = unsafe { ctx.read_at(24)? };

    // Get or create stats entry
    let mut stats = unsafe {
        STATS_MAP.get(&tp_id).copied().unwrap_or(StatsValue {
            count: 0,
            total_ns: 0,
            min_ns: u64::MAX,
            max_ns: 0,
        })
    };

    // Update statistics
    stats.count += 1;
    stats.total_ns += duration_ns;
    if duration_ns > 0 && duration_ns < stats.min_ns {
        stats.min_ns = duration_ns;
    }
    if duration_ns > stats.max_ns {
        stats.max_ns = duration_ns;
    }

    unsafe {
        STATS_MAP.insert(&tp_id, &stats, 0)?;
    }

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
