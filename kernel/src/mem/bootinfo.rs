use crate::mem::addr::{AddrRange, PhysAddr};

#[derive(Copy, Clone, Debug)]
pub struct KernelSegments {
    pub kernel_base_phys: PhysAddr,
    pub bss_phys: AddrRange<PhysAddr>,
    pub stack_phys: AddrRange<PhysAddr>,
    pub free_ram_phys: AddrRange<PhysAddr>,
}

#[derive(Copy, Clone, Debug)]
pub struct KernelBootInfo {
    pub segments: KernelSegments,
}
