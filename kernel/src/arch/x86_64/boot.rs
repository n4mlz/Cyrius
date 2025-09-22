use core::cell::SyncUnsafeCell;
use core::mem::MaybeUninit;
use core::slice;

use bootloader_api::BootInfo as X86EarlyInput;
use bootloader_api::entry_point;
use bootloader_api::info::MemoryRegionKind;

use crate::arch::api::ArchPlatform;
use crate::arch::x86_64::{X86_64, X86BootInfo};
use crate::boot::{
    self, BootInfo, CpuId, FirmwareRegion, KernelImage, MemoryMap, PhysicalRegion,
    PhysicalRegionKind,
};
use crate::mem::addr::{Addr, AddrRange, PhysAddr, VirtAddr};

const MAX_MEMORY_REGIONS: usize = 128;

static REGION_STORAGE: SyncUnsafeCell<[MaybeUninit<PhysicalRegion>; MAX_MEMORY_REGIONS]> =
    SyncUnsafeCell::new([MaybeUninit::uninit(); MAX_MEMORY_REGIONS]);

entry_point!(arch_early_entry);

fn arch_early_entry(early_input: &'static mut X86EarlyInput) -> ! {
    unsafe {
        let boot_info = X86_64::build_boot_info(early_input);
        boot::enter_kernel(boot_info);
    }
}

pub(crate) unsafe fn build_boot_info(
    boot_info: &'static mut X86EarlyInput,
) -> BootInfo<X86BootInfo> {
    let mut count = 0;
    let storage_ptr = {
        let storage = unsafe { &mut *REGION_STORAGE.get() };

        for region in boot_info.memory_regions.iter() {
            if count >= MAX_MEMORY_REGIONS {
                break;
            }

            let kind = match region.kind {
                MemoryRegionKind::Usable => PhysicalRegionKind::Usable,
                MemoryRegionKind::Bootloader => PhysicalRegionKind::Bootloader,
                MemoryRegionKind::UnknownUefi(tag) => {
                    PhysicalRegionKind::Firmware(FirmwareRegion::Uefi(tag))
                }
                MemoryRegionKind::UnknownBios(tag) => {
                    PhysicalRegionKind::Firmware(FirmwareRegion::Bios(tag))
                }
                _ => PhysicalRegionKind::Unknown,
            };

            let phys_range = AddrRange {
                start: PhysAddr::from_usize(region.start as usize),
                end: PhysAddr::from_usize(region.end as usize),
            };

            storage[count].write(PhysicalRegion {
                range: phys_range,
                kind,
            });
            count += 1;
        }

        storage.as_ptr()
    };
    let regions = unsafe { slice::from_raw_parts(storage_ptr as *const PhysicalRegion, count) };
    let memory_map = MemoryMap::new(regions);

    let kernel_image = KernelImage {
        physical: AddrRange {
            start: PhysAddr::from_usize(boot_info.kernel_addr as usize),
            end: PhysAddr::from_usize((boot_info.kernel_addr + boot_info.kernel_len) as usize),
        },
        virtual_offset: boot_info.kernel_image_offset as isize,
    };

    let arch_data = X86BootInfo {
        physical_memory_offset: boot_info
            .physical_memory_offset
            .into_option()
            .map(|offset| VirtAddr::from_usize(offset as usize)),
        recursive_index: boot_info.recursive_index.into_option(),
    };

    BootInfo::new(memory_map, kernel_image, CpuId::BOOT, arch_data)
}
