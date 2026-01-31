// mod hvc;
// mod ivc;

pub mod config;
pub mod images;
pub mod timer;
pub mod vm_list;

use axvm::{AxVMConfig, VmId};

#[cfg(feature = "ebpf")]
use axebpf::tracepoints::{trace_vm_create, trace_vm_boot};
#[cfg(feature = "ebpf")]
use axebpf::trace_ops::AxKops;
#[cfg(feature = "ebpf")]
use axebpf::tracepoint::KernelTraceOps;

/// Initialize the VMM.
///
/// This function creates the VM structures and sets up the primary VCpu for each VM.
pub fn init() {
    info!("Initializing VMM...");
    axvm::enable_viretualization().unwrap();
}

pub fn start_preconfigured_vms() -> anyhow::Result<()> {
    // Initialize guest VM according to config file.
    for config in config::get_guest_prelude_vmconfig()? {
        let vm_config = config::build_vmconfig(config)?;
        start_vm(vm_config)?;
    }
    Ok(())
}

pub fn start_vm(config: AxVMConfig) -> anyhow::Result<VmId> {
    #[cfg(feature = "ebpf")]
    let create_start = AxKops::time_now();

    debug!("Starting guest VM `{}`", config.name());

    let vm = axvm::Vm::new(config)?;

    #[cfg(feature = "ebpf")]
    {
        let vm_id = usize::from(vm.id()) as u32;
        let vcpu_num = vm.vcpu_num() as u32;
        let memory_size = vm.memory_size() as u64;
        trace_vm_create(vm_id, vcpu_num, memory_size);
    }

    let vm = vm_list::push_vm(vm);

    #[cfg(feature = "ebpf")]
    let boot_start = AxKops::time_now();

    vm.boot()?;

    #[cfg(feature = "ebpf")]
    {
        let vm_id = usize::from(vm.id()) as u32;
        let duration = AxKops::time_now().saturating_sub(boot_start);
        trace_vm_boot(vm_id, duration);
    }

    Ok(vm.id())
}

pub fn wait_for_all_vms_exit() {
    let ls = vm_list::get_vm_list();
    for vm in ls.iter() {
        vm.wait().unwrap();
    }
}
