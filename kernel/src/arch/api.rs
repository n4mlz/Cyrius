use crate::boot::BootInfo;
use crate::mem::addr::{AddrRange, PhysAddr, VirtAddr};
use crate::mem::paging::MapError;

pub trait ArchMmu<ArchData> {
    fn init(&self, boot_info: &BootInfo<ArchData>);

    fn map_heap(
        &self,
        boot_info: &BootInfo<ArchData>,
        region: AddrRange<PhysAddr>,
    ) -> Result<AddrRange<VirtAddr>, MapError>;

    fn phys_to_virt(&self, phys: PhysAddr) -> Option<VirtAddr>;
}

pub trait ArchPlatform {
    /// Information received from the bootloader
    type ArchEarlyInput;
    /// the architecture-specific portion of the information passed to the portable kernel core
    type ArchBootInfo;
    /// Architecture-specific MMU provider
    type ArchMmu: ArchMmu<Self::ArchBootInfo>;

    fn name() -> &'static str;

    /// build a BootInfo object that abstracts away architecture-specific boot information.
    ///
    /// # Safety
    /// This function runs before Rust global invariants are established and may access raw pointers.
    unsafe fn build_boot_info(input: Self::ArchEarlyInput) -> BootInfo<Self::ArchBootInfo>;

    /// Called before the portable kernel runs to perform architecture-specific initialization.
    fn init(boot_info: &BootInfo<Self::ArchBootInfo>);

    /// Returns the architecture-specific MMU abstraction.
    fn mmu() -> &'static Self::ArchMmu;
}

pub trait ArchDevice {
    fn console() -> &'static dyn crate::device::char::uart::Uart<Error = ()>;
}
