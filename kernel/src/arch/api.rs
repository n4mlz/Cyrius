use crate::boot::BootInfo;
use crate::mem::addr::{Addr, AddrRange, MemPerm, PhysAddr, VirtAddr};
use crate::mem::frame::FrameAllocator;
use crate::mem::paging::{MapError, UnmapError};

#[derive(Copy, Clone, Debug)]
pub struct KernelLayoutRequest {
    pub heap_phys: AddrRange<PhysAddr>,
    pub map_phys_window: bool,
}

impl KernelLayoutRequest {
    pub const fn new(heap_phys: AddrRange<PhysAddr>, map_phys_window: bool) -> Self {
        Self {
            heap_phys,
            map_phys_window,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct DirectMapRegion {
    pub phys_start: PhysAddr,
    pub virt_start: VirtAddr,
    pub length: usize,
}

impl DirectMapRegion {
    pub fn contains_phys(&self, phys: PhysAddr) -> bool {
        let base = phys.as_usize();
        let start = self.phys_start.as_usize();
        base >= start && base < start + self.length
    }

    pub fn contains_virt(&self, virt: VirtAddr) -> bool {
        let base = virt.as_usize();
        let start = self.virt_start.as_usize();
        base >= start && base < start + self.length
    }
}

#[derive(Copy, Clone, Debug)]
pub struct KernelVirtLayout {
    pub heap: AddrRange<VirtAddr>,
    pub phys_window: Option<DirectMapRegion>,
}

pub trait ArchMmu<ArchData> {
    /// Perform the earliest architecture-specific MMU setup.
    ///
    /// This is invoked before the portable kernel issues any mapping requests. Implementations
    /// typically capture bootstrap details (such as recursive paging slots) required later.
    fn early_init(&self, boot_info: &BootInfo<ArchData>) -> Result<(), MapError>;

    /// Construct the shared kernel virtual memory layout requested by the portable core.
    ///
    /// Successful completion guarantees that all architectures expose an equivalent heap region and
    /// optional direct-mapped window before entering `kernel_main`.
    fn prepare_kernel_layout(
        &self,
        boot_info: &BootInfo<ArchData>,
        request: KernelLayoutRequest,
    ) -> Result<KernelVirtLayout, MapError>;

    fn map(
        &self,
        virt: AddrRange<VirtAddr>,
        phys: AddrRange<PhysAddr>,
        perm: MemPerm,
        allocator: &mut dyn FrameAllocator,
    ) -> Result<(), MapError>;

    fn unmap(&self, virt: AddrRange<VirtAddr>) -> Result<(), UnmapError>;

    fn phys_to_virt(&self, phys: PhysAddr) -> Option<VirtAddr>;

    fn virt_to_phys(&self, virt: VirtAddr) -> Option<PhysAddr>;

    /// Retrieve the cached kernel layout once it has been prepared.
    ///
    /// Intended for diagnostics or late-stage initialization that needs to inspect the layout
    /// without mutating it.
    fn kernel_layout(&self) -> Option<KernelVirtLayout>;
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
