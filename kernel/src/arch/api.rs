use bootloader_api::BootInfo;

use crate::mem::addr::{AddrRange, VirtAddr};

pub trait ArchPlatform {
    fn name() -> &'static str;
}

pub trait ArchDevice {
    fn console() -> &'static dyn crate::device::char::uart::Uart<Error = ()>;
}

pub trait ArchTrap {
    type Frame: crate::trap::TrapFrame;

    fn init_traps();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapRegionError {
    MissingPhysicalMapping,
    NoUsableRegion,
    AddressOverflow,
}

pub trait ArchMemory {
    fn locate_kernel_heap(
        boot_info: &'static BootInfo,
    ) -> Result<AddrRange<VirtAddr>, HeapRegionError>;
}
