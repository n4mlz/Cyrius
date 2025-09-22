use crate::arch::{Arch, api::ArchPlatform};
use crate::mem::addr::{AddrRange, PhysAddr};

/// Identifier of the CPU that invoked the kernel entry point.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CpuId(pub usize);

impl CpuId {
    pub const BOOT: Self = Self(0);
}

/// Describes a physical memory interval.
#[derive(Copy, Clone, Debug)]
pub struct PhysicalRegion {
    pub range: AddrRange<PhysAddr>,
    pub kind: PhysicalRegionKind,
}

/// Classifies the usage of a physical region at boot time.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PhysicalRegionKind {
    Usable,
    Bootloader,
    Firmware(FirmwareRegion),
    Unknown,
}

/// Distinguishes firmware specific memory types we want to keep track of.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FirmwareRegion {
    Uefi(u32), // UEFI memory type
    Bios(u32), // BIOS memory type
}

/// Immutable view over the system memory layout at boot.
#[derive(Clone, Copy, Debug)]
pub struct MemoryMap<'a> {
    regions: &'a [PhysicalRegion],
}

impl<'a> MemoryMap<'a> {
    pub const fn new(regions: &'a [PhysicalRegion]) -> Self {
        Self { regions }
    }

    pub fn regions(&self) -> &'a [PhysicalRegion] {
        self.regions
    }

    pub fn iter(&self) -> impl Iterator<Item = &'a PhysicalRegion> {
        self.regions.iter()
    }
}

/// Captures where the kernel image resides in memory.
#[derive(Copy, Clone, Debug)]
pub struct KernelImage {
    pub physical: AddrRange<PhysAddr>,
    pub virtual_offset: isize,
}

/// Fully prepared data passed from architecture specific initialization to the portable kernel core.
pub struct BootInfo<ArchData> {
    pub memory_map: MemoryMap<'static>,
    pub kernel_image: KernelImage,
    pub boot_cpu: CpuId,
    pub arch_data: ArchData,
}

impl<ArchData> BootInfo<ArchData> {
    pub fn new(
        memory_map: MemoryMap<'static>,
        kernel_image: KernelImage,
        boot_cpu: CpuId,
        arch_data: ArchData,
    ) -> Self {
        Self {
            memory_map,
            kernel_image,
            boot_cpu,
            arch_data,
        }
    }
}

/// Transfers control to the architecture independent kernel core.
pub fn enter_kernel(boot_info: BootInfo<<Arch as ArchPlatform>::ArchBootInfo>) -> ! {
    crate::kernel_main(boot_info)
}
