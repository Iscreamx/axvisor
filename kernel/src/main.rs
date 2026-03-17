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

/// 512 KB reserved for kallsyms symbol table.
/// `rust-objcopy --update-section` replaces this with actual data after build.
#[cfg(feature = "ebpf")]
const KALLSYMS_RESERVE_SIZE: usize = 512 * 1024;

#[cfg(feature = "ebpf")]
#[unsafe(link_section = ".kallsyms")]
#[used]
static KALLSYMS_PLACEHOLDER: [u8; KALLSYMS_RESERVE_SIZE] = [0u8; KALLSYMS_RESERVE_SIZE];

#[unsafe(no_mangle)]
fn main() {
    logo::print_logo();

    // Initialize eBPF tracepoint subsystem with symbol table for kprobe support
    #[cfg(feature = "ebpf")]
    {
        // Linker-provided labels for the .kallsyms section injected by
        // `rust-objcopy --update-section` after build (see xtask symbols).
        unsafe extern "C" {
            static _kallsyms_start: u8;
            static _kallsyms_end: u8;
            static _stext: u8;
            static _etext: u8;
        }

        let kallsyms_data = unsafe {
            let ptr = &_kallsyms_start as *const u8;
            let len = (&_kallsyms_end as *const u8).offset_from(ptr) as usize;
            core::slice::from_raw_parts(ptr, len)
        };
        let stext = unsafe { &_stext as *const u8 as u64 };
        let etext = unsafe { &_etext as *const u8 as u64 };

        axebpf::init_with_symbols(kallsyms_data, stext, etext);
    }

    info!("Starting virtualization...");
    // info!("Hardware support: {:?}", axvm::has_hardware_support());

    vmm::init();

    #[cfg(feature = "ebpf")]
    axebpf::tracepoints::trace_vmm_init(4u32, 0);

    vmm::start_preconfigured_vms().unwrap();

    info!("[OK] Default guest initialized");
    vmm::wait_for_all_vms_exit();
    info!("All guest VMs exited.");
    shell::bind_current_thread_to_non_boot_cpus();
    shell::console_init();
}
