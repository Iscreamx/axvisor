/// 追踪点上下文，与 axebpf::TraceContext 保持一致
#[repr(C)]
pub struct TraceContext {
    pub tracepoint_id: u32,
    pub timestamp_ns: u64,
    pub vm_id: u32,
    pub vcpu_id: u32,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
}
