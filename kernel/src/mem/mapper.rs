use crate::mem::addr::{MemPerm, Page, PhysAddr, VirtAddr};

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
