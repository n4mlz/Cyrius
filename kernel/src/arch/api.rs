use bootloader_api::BootInfo;

use crate::mem::allocator::{HeapRegion, MemoryError};

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

pub trait ArchMemory {
    fn heap_region(boot_info: &'static BootInfo) -> Result<HeapRegion, MemoryError>;
}
