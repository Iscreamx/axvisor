use alloc::collections::BTreeMap;
use axstd::sync::Mutex;
use axerrno::{AxResult, ax_err_type};
use memory_addr::{PAGE_SIZE_4K, VirtAddr};
use axstd::os::arceos::modules::axalloc;

#[derive(Clone)]
pub struct ConsoleBuffer {
    pub owner_vm_id: usize,
    pub peer_vm_id: usize,
    pub buffer_base: VirtAddr,
    pub buffer_size: usize,
}

#[derive(Clone)]
struct ConsoleConnectionEntry {
    buf1: ConsoleBuffer,
    buf2: ConsoleBuffer,
    ref_count: usize,
}

// Global connection table: allocate a pair of buffers for each VM pair
static CONSOLE_CONNECTIONS: Mutex<BTreeMap<(usize, usize), ConsoleConnectionEntry>> =
    Mutex::new(BTreeMap::new());

impl ConsoleBuffer {
    pub fn alloc(buffer_size: usize, owner_vm_id: usize, peer_vm_id: usize) -> AxResult<Self> {
        let num_frames = (buffer_size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K;
        let buffer_base = axalloc::global_allocator()
            .alloc(
                core::alloc::Layout::from_size_align(
                    num_frames * PAGE_SIZE_4K,
                    PAGE_SIZE_4K,
                ).unwrap()
            )
            .map(|nn| VirtAddr::from(nn.as_ptr() as usize))
            .map_err(|_| ax_err_type!(NoMemory, "Failed to allocate console buffer"))?;
        unsafe {
            core::ptr::write_bytes(buffer_base.as_mut_ptr(), 0, num_frames * PAGE_SIZE_4K);
        }
        info!("Allocated console buffer at {:#x}, size {}, owner_vm_id={}, peer_vm_id={}",
            buffer_base.as_usize(), buffer_size, owner_vm_id, peer_vm_id);

        Ok(Self {
            buffer_base,
            buffer_size,
            owner_vm_id,
            peer_vm_id,
        })
    }

    pub fn dealloc(&self) {
        let num_frames = (self.buffer_size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K;
        info!("Deallocating console buffer at {:#x}, size {}", self.buffer_base.as_usize(), self.buffer_size);
        axalloc::global_allocator().dealloc(
            unsafe { core::ptr::NonNull::new_unchecked(self.buffer_base.as_usize() as *mut u8) },
            core::alloc::Layout::from_size_align(num_frames * PAGE_SIZE_4K, PAGE_SIZE_4K).unwrap(),
        );
    }
}

pub struct ConsoleConnectionManager;

impl ConsoleConnectionManager {

    /// Establish a connection and return buffers for both sides
    pub fn establish_connection(vm1: usize, vm2: usize, buffer_size: usize) -> AxResult<(ConsoleBuffer, ConsoleBuffer)> {
        let mut connections = CONSOLE_CONNECTIONS.lock();
        // Check if connection exists
        if connections.contains_key(&(vm1, vm2)) {
            // Update ref_count for both sides to keep them in sync
            if let Some(entry) = connections.get_mut(&(vm1, vm2)) {
                entry.ref_count += 1;
            }
            if let Some(entry) = connections.get_mut(&(vm2, vm1)) {
                entry.ref_count += 1;
            }
            
            let entry = connections.get(&(vm1, vm2)).unwrap();
            info!("Reusing existing buffers for VM[{}]<->VM[{}], ref_count={}", vm1, vm2, entry.ref_count);
            return Ok((entry.buf1.clone(), entry.buf2.clone()));
        }
        // Allocate two new buffers
        let buf1 = ConsoleBuffer::alloc(buffer_size, vm1, vm2)?;
        let buf2 = ConsoleBuffer::alloc(buffer_size, vm2, vm1)?;

        // Initial ref_count is 1 (only the caller VM is referencing it so far)
        let entry = ConsoleConnectionEntry {
            buf1: buf1.clone(),
            buf2: buf2.clone(),
            ref_count: 1,
        };
        connections.insert((vm1, vm2), entry.clone());
        connections.insert((vm2, vm1), ConsoleConnectionEntry {
            buf1: buf2.clone(),
            buf2: buf1.clone(),
            ref_count: 1,
        });
        info!("Allocated new buffers for VM[{}]<->VM[{}]", vm1, vm2);
        Ok((buf1, buf2))
    }

    /// Remove a connection and deallocate buffers
    pub fn remove_connection(vm1: usize, vm2: usize) {
        let mut connections = CONSOLE_CONNECTIONS.lock();
        
        // Check if connection exists
        if !connections.contains_key(&(vm1, vm2)) {
            return;
        }

        // Decrement ref_count for both sides
        let mut new_count = 0;
        if let Some(entry) = connections.get_mut(&(vm1, vm2)) {
            if entry.ref_count > 0 {
                entry.ref_count -= 1;
            }
            new_count = entry.ref_count;
        }
        if let Some(entry) = connections.get_mut(&(vm2, vm1)) {
            if entry.ref_count > 0 {
                entry.ref_count -= 1;
            }
        }

        info!("Decremented ref_count for VM[{}]<->VM[{}], now {}", vm1, vm2, new_count);

        // Only deallocate when ref_count drops to 0
        if new_count == 0 {
            if let Some(entry) = connections.remove(&(vm1, vm2)) {
                entry.buf1.dealloc();
                entry.buf2.dealloc();
            }
            // Remove the reverse mapping as well (buffers already deallocated above)
            connections.remove(&(vm2, vm1));
            info!("Deallocated buffers for VM[{}]<->VM[{}]", vm1, vm2);
        }
        connections.remove(&(vm2, vm1));
    }
    
    /// Get the buffers for a VM pair
    pub fn get_buffers(vm1: usize, vm2: usize) -> Option<(ConsoleBuffer, ConsoleBuffer)> {
        let connections = CONSOLE_CONNECTIONS.lock();
        connections.get(&(vm1, vm2)).map(|entry| (entry.buf1.clone(), entry.buf2.clone()))
    }

}
