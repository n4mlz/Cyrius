use crate::mem::addr::{MemPerm, Page, PhysAddr, VirtAddr};
use crate::mem::frame::FrameAllocator;

#[derive(Debug)]
pub enum MapError {
    AlreadyMapped,
    OutOfMemory,
    InvalidAddress,
    Unsupported,
}

#[derive(Debug)]
pub enum UnmapError {
    NotMapped,
    InvalidAddress,
}

pub trait PageTable {
    fn map(
        &mut self,
        virt: Page<VirtAddr>,
        phys: Page<PhysAddr>,
        perm: MemPerm,
        allocator: &mut dyn FrameAllocator,
    ) -> Result<(), MapError>;

    fn unmap(&mut self, virt: Page<VirtAddr>) -> Result<(), UnmapError>;
}

pub trait AddressSpace {
    fn map(
        &mut self,
        virt: Page<VirtAddr>,
        phys: Page<PhysAddr>,
        perm: MemPerm,
        allocator: &mut dyn FrameAllocator,
    ) -> Result<(), MapError>;

    fn unmap(&mut self, virt: Page<VirtAddr>) -> Result<(), UnmapError>;

    fn activate(&self);
}

pub trait AddressSpaceManager {
    type Space: AddressSpace;

    fn new_space(&self, allocator: &mut dyn FrameAllocator) -> Result<Self::Space, MapError>;

    fn current_space(&self) -> Self::Space;

    fn set_space(&self, space: &Self::Space);
}
