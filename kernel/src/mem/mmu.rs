use crate::mem::{
    bootinfo::KernelBootInfo,
    mapper::{AddressSpace, PageMapper},
};

pub trait ArchMmu {
    type Mapper: PageMapper;

    type Space: AddressSpace;

    /// Create kernel address space
    ///
    /// # Safety
    ///
    /// This function guarantees the following:
    /// 1. Create page table and enable MMU
    /// 2. Map kernel text/rodata/data/bss/stack to appropriate virtual addresses
    /// 3. Exception handlers are reachable
    /// 4. Returned Space/Mapper are already valid
    unsafe fn create_kernel_space(kbi: &KernelBootInfo) -> (Self::Space, Self::Mapper);

    /// Create user address space (with kernel template)
    ///
    /// # Safety
    ///
    /// Since kernel region is shared, the caller must guarantee
    /// the integrity of the kernel region
    unsafe fn create_user_space_with_kernel_template(
        kernel_template: &Self::Space,
    ) -> (Self::Space, Self::Mapper);
}
