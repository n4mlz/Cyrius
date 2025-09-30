pub mod addr;
pub mod allocator;

use bootloader_api::BootInfo;

use crate::arch::{Arch, api::ArchMemory};

pub use allocator::{AllocatorInitError, HeapRegion, HeapRegionError, MemoryError};

#[derive(Debug)]
pub enum InitError {
    Memory(MemoryError),
    Allocator(AllocatorInitError),
}

pub fn init(boot_info: &'static BootInfo) -> Result<(), InitError> {
    let region = Arch::heap_region(boot_info).map_err(InitError::Memory)?;
    allocator::init(region).map_err(InitError::Allocator)?;
    Ok(())
}
