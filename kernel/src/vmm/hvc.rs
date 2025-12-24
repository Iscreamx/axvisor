use axaddrspace::{GuestPhysAddr, MappingFlags};
use axerrno::{AxResult, ax_err, ax_err_type};
use axhvc::{HyperCallCode, HyperCallResult};
use alloc::vec::Vec;
use cpumask::CpuMask;

use crate::vmm::ivc::{self, IVCChannel};
use crate::vmm::{VCpuRef, VMRef, vm_list};
use crate::vmm::console::ConsoleConnectionManager;

pub struct HyperCall {
    _vcpu: VCpuRef,
    vm: VMRef,
    code: HyperCallCode,
    args: [u64; 6],
}

impl HyperCall {
    pub fn new(vcpu: VCpuRef, vm: VMRef, code: u64, args: [u64; 6]) -> AxResult<Self> {
        let code = HyperCallCode::try_from(code as u32).map_err(|e| {
            warn!("Invalid hypercall code: {code} e {e:?}");
            ax_err_type!(InvalidInput)
        })?;

        Ok(Self {
            _vcpu: vcpu,
            vm,
            code,
            args,
        })
    }

    pub fn execute(&self) -> HyperCallResult {
        match self.code {
            HyperCallCode::HIVCPublishChannel => {
                let key = self.args[0] as usize;
                let shm_base_gpa_ptr = GuestPhysAddr::from_usize(self.args[1] as usize);
                let shm_size_ptr = GuestPhysAddr::from_usize(self.args[2] as usize);

                info!(
                    "VM[{}] HyperCall {:?} key {:#x}",
                    self.vm.id(),
                    self.code,
                    key
                );
                // User will pass the size of the shared memory region,
                // we will allocate the shared memory region based on this size.
                let shm_region_size = self.vm.read_from_guest_of::<usize>(shm_size_ptr)?;
                let (shm_base_gpa, shm_region_size) = self.vm.alloc_ivc_channel(shm_region_size)?;

                let ivc_channel =
                    IVCChannel::alloc(self.vm.id(), key, shm_region_size, shm_base_gpa)?;

                let actual_size = ivc_channel.size();

                self.vm.map_region(
                    shm_base_gpa,
                    ivc_channel.base_hpa(),
                    actual_size,
                    MappingFlags::READ | MappingFlags::WRITE,
                )?;

                self.vm
                    .write_to_guest_of(shm_base_gpa_ptr, &shm_base_gpa.as_usize())?;
                self.vm.write_to_guest_of(shm_size_ptr, &actual_size)?;

                ivc::insert_channel(self.vm.id(), ivc_channel)?;

                Ok(0)
            }
            HyperCallCode::HIVCUnPublishChannel => {
                let key = self.args[0] as usize;

                info!(
                    "VM[{}] HyperCall {:?} with key {:#x}",
                    self.vm.id(),
                    self.code,
                    key
                );
                let (base_gpa, size) = ivc::unpublish_channel(self.vm.id(), key)?.unwrap();
                self.vm.unmap_region(base_gpa, size)?;

                Ok(0)
            }
            HyperCallCode::HIVCSubscribChannel => {
                let publisher_vm_id = self.args[0] as usize;
                let key = self.args[1] as usize;
                let shm_base_gpa_ptr = GuestPhysAddr::from_usize(self.args[2] as usize);
                let shm_size_ptr = GuestPhysAddr::from_usize(self.args[3] as usize);

                info!(
                    "VM[{}] HyperCall {:?} to VM[{}]",
                    self.vm.id(),
                    self.code,
                    publisher_vm_id
                );

                let shm_size = ivc::get_channel_size(publisher_vm_id, key)?;
                let (shm_base_gpa, _) = self.vm.alloc_ivc_channel(shm_size)?;

                let (base_hpa, actual_size) = ivc::subscribe_to_channel_of_publisher(
                    publisher_vm_id,
                    key,
                    self.vm.id(),
                    shm_base_gpa,
                )?;

                // TODO: seperate the mapping flags of metadata and data.
                self.vm.map_region(
                    shm_base_gpa,
                    base_hpa,
                    actual_size,
                    MappingFlags::READ | MappingFlags::WRITE,
                )?;

                self.vm
                    .write_to_guest_of(shm_base_gpa_ptr, &shm_base_gpa.as_usize())?;
                self.vm.write_to_guest_of(shm_size_ptr, &actual_size)?;

                info!(
                    "VM[{}] HyperCall HIVC_REGISTER_SUBSCRIBER success, base GPA: {:#x}, size: {}",
                    self.vm.id(),
                    shm_base_gpa,
                    actual_size
                );

                Ok(0)
            }
            HyperCallCode::HIVCUnSubscribChannel => {
                let publisher_vm_id = self.args[0] as usize;
                let key = self.args[1] as usize;

                info!(
                    "VM[{}] HyperCall {:?} from VM[{}]",
                    self.vm.id(),
                    self.code,
                    publisher_vm_id
                );
                let (base_gpa, size) =
                    ivc::unsubscribe_from_channel_of_publisher(publisher_vm_id, key, self.vm.id())?;
                self.vm.unmap_region(base_gpa, size)?;

                Ok(0)
            }
                        HyperCallCode::HConEstablishConnect => {
                info!(
                    "VM[{}] HyperCall {:?}",
                    self.vm.id(),
                    self.code,
                );
                let num_ids = self.args[1] as usize;
                let ids: Vec<usize> = self.args[2..2+num_ids].iter().map(|&id| id as usize).collect();
                info!(
                    "Establishing connection between VM[{}] and VM IDs: {:?}",
                    self.vm.id(),
                    ids
                );

                let buffer_size = 4096;
                let mut owner_vm_ids = Vec::new();
                let mut peer_vm_ids = Vec::new();
                let mut buffer_addrs = Vec::new();

                for &dst_vm_id in &ids {
                    let (buf_src_to_dst, buf_dst_to_src) =
                        ConsoleConnectionManager::establish_connection(self.vm.id(), dst_vm_id, buffer_size)
                            .map_err(|e| {
                                warn!("Failed to allocate console buffer for VM[{}]<->VM[{}]: {:?}", self.vm.id(), dst_vm_id, e);
                                ax_err_type!(NoMemory)
                            })?;
                    // Send buffer (this VM -> peer)
                    owner_vm_ids.push(buf_src_to_dst.owner_vm_id);
                    peer_vm_ids.push(buf_src_to_dst.peer_vm_id);
                    buffer_addrs.push(buf_src_to_dst.buffer_base.as_usize());

                    // Receive buffer (peer -> this VM)
                    owner_vm_ids.push(buf_dst_to_src.owner_vm_id);
                    peer_vm_ids.push(buf_dst_to_src.peer_vm_id);
                    buffer_addrs.push(buf_dst_to_src.buffer_base.as_usize());
                }

                // Batch update devices (update both send and receive buffers)
                let _ = self.vm.establish_console_connection(
                    &owner_vm_ids,
                    &peer_vm_ids,
                    &buffer_addrs,
                );

                Ok(0)
            }
            HyperCallCode::HConUnEstablishConnect => {
                info!(
                    "VM[{}] HyperCall {:?}",
                    self.vm.id(),
                    self.code,
                );
                let num_ids = self.args[1] as usize;
                let ids: Vec<usize> = self.args[2..2+num_ids].iter().map(|&id| id as usize).collect();
                info!(
                    "Removing connection between VM[{}] and VM IDs: {:?}",
                    self.vm.id(),
                    ids
                );

                let mut owner_vm_ids = Vec::new();
                let mut peer_vm_ids = Vec::new();

                for &dst_vm_id in &ids {
                    // Find the allocated buffer and get owner and peer
                    if let Some((buf_src_to_dst, buf_dst_to_src)) = ConsoleConnectionManager::get_buffers(self.vm.id(), dst_vm_id) {
                        owner_vm_ids.push(buf_src_to_dst.owner_vm_id);
                        peer_vm_ids.push(buf_src_to_dst.peer_vm_id);

                        owner_vm_ids.push(buf_dst_to_src.owner_vm_id);
                        peer_vm_ids.push(buf_dst_to_src.peer_vm_id);
                    }
                    ConsoleConnectionManager::remove_connection(self.vm.id(), dst_vm_id);
                }

                // Batch update devices again
                let _ = self.vm.remove_console_connection(
                    &owner_vm_ids,
                    &peer_vm_ids,
                );

                Ok(0)
            }
            HyperCallCode::HIVCSendIPI => {
                let target_vm_id = self.args[1] as usize;
                let target_vcpu_id = self.args[2] as usize;
                let vector = self.args[3] as usize;

                info!(
                    "VM[{}] HyperCall HIVCSendIpi: Injecting IRQ {} to VM[{}] vCPU[{}]",
                    self.vm.id(),
                    vector,
                    target_vm_id,
                    target_vcpu_id
                );

                if let Some(target_vm) = vm_list::get_vm_by_id(target_vm_id) {
                    let mask = CpuMask::one_shot(target_vcpu_id);

                    if let Err(e) = target_vm.inject_interrupt_to_vcpu(mask, vector) {
                        warn!("Failed to inject interrupt: {:?}", e);
                    }
                } else {
                    warn!("Target VM {} not found", target_vm_id);
                }
                Ok(0)
            }
            _ => {
                warn!("Unsupported hypercall code: {:?}", self.code);
                ax_err!(Unsupported)?
            }
        }
    }
}
