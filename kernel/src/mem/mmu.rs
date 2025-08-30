use crate::mem::{
    addr::{MemPerm, Page, PhysAddr, VirtAddr},
    bootinfo::KernelBootInfo,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MapError {
    AlignmentError,
    OutOfMemory,
    InvalidRange,
    AlreadyMapped,
}

pub trait PageMapper {
    /// Map a virtual page to a physical page
    /// VirtAddr and PhysAddr must be aligned to page size
    fn map(
        &mut self,
        vp: Page<VirtAddr>,
        pf: Page<PhysAddr>,
        perm: MemPerm,
    ) -> Result<(), MapError>;

    /// Unmap a virtual page
    /// VirtAddr and PhysAddr must be aligned to page size
    fn unmap(&mut self, vp: Page<VirtAddr>) -> Result<(), MapError>;

    fn set_perm(&mut self, vp: Page<VirtAddr>, perm: MemPerm) -> Result<(), MapError>;
}

pub trait AddressSpace {
    /// Activate this address space
    ///
    /// # Safety
    ///
    /// The caller must guarantee the following:
    /// - The page table is valid and not corrupted
    /// - Kernel region is properly mapped
    /// - Exception handlers are reachable
    unsafe fn activate(&self);

    fn flush_tlb(&self);
}

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
