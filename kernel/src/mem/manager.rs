use bootloader_api::BootInfo;

use crate::mem::addr::{AddrRange, PhysAddr};

use super::frame::{FRAME_ALLOCATOR, FrameAllocatorGuard, FrameAllocatorInitError};
use super::mapper::{OffsetMapper, PHYS_MAPPER, PhysMapperInitError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryInitError {
    Frame(FrameAllocatorInitError),
    Mapper(PhysMapperInitError),
}

pub fn init(
    boot_info: &'static BootInfo,
    reserved: &[AddrRange<PhysAddr>],
) -> Result<(), MemoryInitError> {
    FRAME_ALLOCATOR
        .init(boot_info, reserved)
        .map_err(MemoryInitError::Frame)?;

    let offset = boot_info.physical_memory_offset.as_ref().copied();
    PHYS_MAPPER.init(offset).map_err(MemoryInitError::Mapper)?;

    Ok(())
}

pub fn frame_allocator() -> FrameAllocatorGuard<'static> {
    FRAME_ALLOCATOR.lock()
}

pub fn phys_mapper() -> OffsetMapper {
    PHYS_MAPPER.mapper()
}
