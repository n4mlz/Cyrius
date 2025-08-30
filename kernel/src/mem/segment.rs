use crate::mem::addr::{AddrRange, PhysAddr};

pub struct KernelSegments {
    pub base: PhysAddr,
    pub bss: AddrRange<PhysAddr>,
    pub stack_top: PhysAddr,
    pub free_ram: AddrRange<PhysAddr>,
}
