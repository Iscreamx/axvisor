// mod hvc;
// mod ivc;

pub mod config;
pub mod images;
pub mod timer;
pub mod vm_list;

#[cfg(all(feature = "guest-kprobe", target_arch = "aarch64"))]
use memory_addr::MemoryAddr;

use axvm::{AxVMConfig, VmId};

#[cfg(all(feature = "guest-kprobe", target_arch = "aarch64"))]
fn register_guest_kprobe_hooks() {
    use axebpf::probe::kprobe::addr_translate::{
        register_gpa_to_hpa_hook, register_guest_pt_read_hook, register_vm_ttbr1_hook,
    };
    use axebpf::probe::kprobe::manager::{
        register_stage2_exec_hook, register_stage2_exec_region_hook,
    };

    register_guest_pt_read_hook(read_guest_pte_for_vm);
    register_vm_ttbr1_hook(read_vm_ttbr1_el1);
    register_gpa_to_hpa_hook(translate_gpa_to_hpa_for_vm);
    register_stage2_exec_hook(update_stage2_exec_for_vm);
    register_stage2_exec_region_hook(query_stage2_exec_region_for_vm);
    axvm::register_post_vmexit_hook(on_guest_vmexit);
    info!("guest_kprobe: VMM address translation hooks registered");
}

#[cfg(all(feature = "guest-kprobe", target_arch = "aarch64"))]
fn on_guest_vmexit(vm_id: u32) {
    let enabled = axebpf::probe::kprobe::manager::try_enable_registered_for_vm(vm_id);
    if enabled > 0 {
        info!(
            "guest_kprobe: auto-enabled {} deferred probe(s) for vm{} after VM-exit",
            enabled,
            vm_id
        );
    }
}

#[cfg(all(feature = "guest-kprobe", target_arch = "aarch64"))]
fn find_vm(vm_id: u32) -> axerrno::AxResult<vm_list::VMRef> {
    vm_list::get_vm_by_id(vm_id as usize)
        .ok_or_else(|| axerrno::ax_err_type!(NotFound, "target VM not found"))
}

#[cfg(all(feature = "guest-kprobe", target_arch = "aarch64"))]
fn read_guest_pte_for_vm(gpa: u64, vm_id: u32) -> axerrno::AxResult<u64> {
    let vm = find_vm(vm_id)?;
    let gpa = usize::try_from(gpa)
        .map_err(|_| axerrno::ax_err_type!(InvalidInput, "GPA out of range"))?;
    vm.read_guest_u64(axvm::GuestPhysAddr::from_usize(gpa))
        .map_err(|e| {
            warn!(
                "guest_kprobe: read guest PTE failed vm{} gpa={:#x}: {}",
                vm_id, gpa, e
            );
            axerrno::AxError::BadState
        })
}

#[cfg(all(feature = "guest-kprobe", target_arch = "aarch64"))]
fn translate_gpa_to_hpa_for_vm(gpa: u64, vm_id: u32) -> axerrno::AxResult<u64> {
    let vm = find_vm(vm_id)?;
    let gpa = usize::try_from(gpa)
        .map_err(|_| axerrno::ax_err_type!(InvalidInput, "GPA out of range"))?;
    let hpa = vm
        .gpa_to_hpa(axvm::GuestPhysAddr::from_usize(gpa))
        .map_err(|e| {
            warn!(
                "guest_kprobe: GPA->HPA translate failed vm{} gpa={:#x}: {}",
                vm_id, gpa, e
            );
            axerrno::AxError::BadState
        })?;
    Ok(hpa.as_usize() as u64)
}

#[cfg(all(feature = "guest-kprobe", target_arch = "aarch64"))]
fn read_vm_ttbr1_el1(vm_id: u32) -> axerrno::AxResult<u64> {
    let vm = find_vm(vm_id)?;
    let ttbr1 = vm.guest_ttbr1_el1();
    if ttbr1 == 0 {
        return Err(axerrno::AxError::BadState);
    }
    Ok(ttbr1)
}

#[cfg(all(feature = "guest-kprobe", target_arch = "aarch64"))]
fn update_stage2_exec_for_vm(vm_id: u32, gpa: u64, executable: bool) -> axerrno::AxResult<()> {
    let vm = find_vm(vm_id)?;
    let gpa = usize::try_from(gpa)
        .map_err(|_| axerrno::ax_err_type!(InvalidInput, "GPA out of range"))?;
    vm.set_gpa_executable(axvm::GuestPhysAddr::from_usize(gpa), executable)
        .map_err(|e| {
            warn!(
                "guest_kprobe: Stage-2 exec update failed vm{} gpa={:#x} executable={} err={}",
                vm_id, gpa, executable, e
            );
            axerrno::AxError::BadState
        })?;
    axvm::invalidate_stage2_tlb_by_vmid(vm_id);
    log::trace!(
        "guest_kprobe: Stage-2 TLBI vm{} gpa={:#x} executable={}",
        vm_id,
        gpa,
        executable
    );
    Ok(())
}

#[cfg(all(feature = "guest-kprobe", target_arch = "aarch64"))]
fn query_stage2_exec_region_for_vm(vm_id: u32, gpa: u64) -> axerrno::AxResult<(u64, u64)> {
    let vm = find_vm(vm_id)?;
    let gpa = usize::try_from(gpa)
        .map_err(|_| axerrno::ax_err_type!(InvalidInput, "GPA out of range"))?;
    let (_, _, page_size) = vm
        .query_gpa_mapping(axvm::GuestPhysAddr::from_usize(gpa))
        .map_err(|e| {
            warn!(
                "guest_kprobe: Stage-2 exec region query failed vm{} gpa={:#x}: {}",
                vm_id, gpa, e
            );
            axerrno::AxError::BadState
        })?;
    let base = gpa.align_down(page_size) as u64;
    Ok((base, page_size as u64))
}

/// Initialize the VMM.
///
/// This function creates the VM structures and sets up the primary VCpu for each VM.
pub fn init() {
    info!("Initializing VMM...");
    axvm::enable_viretualization().unwrap();
    #[cfg(all(feature = "guest-kprobe", target_arch = "aarch64"))]
    register_guest_kprobe_hooks();
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
    debug!("Starting guest VM `{}`", config.name());

    let vm = axvm::Vm::new(config)?;

    let vm = vm_list::push_vm(vm);

    vm.boot()?;

    Ok(vm.id())
}

pub fn wait_for_all_vms_exit() {
    let ls = vm_list::get_vm_list();
    for vm in ls.iter() {
        vm.wait().unwrap();
    }
}
