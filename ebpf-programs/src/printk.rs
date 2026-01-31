#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};

/// Counter Map: tracepoint_id -> invocation count
#[map]
static COUNTER_MAP: HashMap<u32, u64> = HashMap::with_max_entries(128, 0);

/// Entry point - reads tracepoint_id from context, increments counter
/// Returns the new count value for hypervisor to print
#[tracepoint]
pub fn printk(ctx: TracePointContext) -> u32 {
    match try_printk(ctx) {
        Ok(count) => count as u32,
        Err(_) => 0xFFFFFFFF,
    }
}

fn try_printk(ctx: TracePointContext) -> Result<u64, i64> {
    // Read tracepoint_id from TraceContext at offset 0
    let tp_id: u32 = unsafe { ctx.read_at(0)? };

    // Get current count and increment
    let count = unsafe { COUNTER_MAP.get(&tp_id).copied().unwrap_or(0) };
    let new_count = count + 1;
    unsafe {
        COUNTER_MAP.insert(&tp_id, &new_count, 0)?;
    }

    // Return count - hypervisor will handle printing with tracepoint name
    Ok(new_count)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
