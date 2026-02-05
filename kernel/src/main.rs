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

    // Initialize eBPF tracepoint subsystem with symbol table for kprobe support
    #[cfg(feature = "ebpf")]
    {
        // Embedded kallsyms binary data with page alignment for ksym library
        // The ksym library requires the blob to be page-aligned in memory.
        #[repr(C, align(4096))]
        struct AlignedKallsyms<const N: usize> {
            data: [u8; N],
        }

        const KALLSYMS_BYTES: &[u8] = include_bytes!("../../kallsyms.bin");
        static KALLSYMS_ALIGNED: AlignedKallsyms<{ include_bytes!("../../kallsyms.bin").len() }> =
            AlignedKallsyms {
                data: *include_bytes!("../../kallsyms.bin"),
            };

        // Get kernel text section boundaries from linker symbols
        unsafe extern "C" {
            static _stext: u8;
            static _etext: u8;
        }
        let stext = unsafe { &_stext as *const u8 as u64 };
        let etext = unsafe { &_etext as *const u8 as u64 };

        axebpf::init_with_symbols(&KALLSYMS_ALIGNED.data, stext, etext);
    }

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
