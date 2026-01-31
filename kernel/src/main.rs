#![no_std]
#![no_main]

#[macro_use]
extern crate log;

#[macro_use]
extern crate alloc;

extern crate axstd as std;
extern crate driver;

// extern crate axruntime;

mod logo;
mod task;
mod shell;
mod vmm;

pub use shell::*;
pub use vmm::*;

#[cfg(feature = "ebpf")]
use axebpf::tracepoint::KernelTraceOps;

#[unsafe(no_mangle)]
fn main() {
    logo::print_logo();

    #[cfg(feature = "ebpf")]
    let init_start = axebpf::trace_ops::AxKops::time_now();

    // Initialize eBPF tracepoint subsystem
    #[cfg(feature = "ebpf")]
    axebpf::init();

    info!("Starting virtualization...");
    // info!("Hardware support: {:?}", axvm::has_hardware_support());

    vmm::init();

    #[cfg(feature = "ebpf")]
    {
        use axebpf::tracepoints::trace_vmm_init;
        use axebpf::trace_ops::AxKops;
        let duration = AxKops::time_now().saturating_sub(init_start);
        // Use a fixed value for now - actual CPU count determined at runtime
        let cpu_count = 4u32;
        trace_vmm_init(cpu_count, duration);
    }

    vmm::start_preconfigured_vms().unwrap();

    info!("[OK] Default guest initialized");
    vmm::wait_for_all_vms_exit();
    info!("All guest VMs exited.");
    shell::console_init();
}
