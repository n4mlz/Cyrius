use core::convert::TryFrom;

use bootloader_api::{BootInfo, info::MemoryRegionKind};

use crate::mem::{
    addr::{Addr, PageSize, PhysAddr, VirtAddr},
    allocator::{HeapRegion, MemoryError},
};

pub fn heap_region(boot_info: &'static BootInfo) -> Result<HeapRegion, MemoryError> {
    let offset = boot_info
        .physical_memory_offset
        .as_ref()
        .copied()
        .ok_or(MemoryError::MissingPhysicalMapping)?;

    // Align heap region to 4 KiB page boundaries
    let align = PageSize::SIZE_4K.bytes();
    let offset_usize = usize::try_from(offset).map_err(|_| MemoryError::AddressOverflow)?;

    let mut best: Option<(VirtAddr, usize)> = None;

    for region in boot_info.memory_regions.iter() {
        if region.kind != MemoryRegionKind::Usable {
            continue;
        }

        let start = PhysAddr::from_raw(region.start);
        let end = PhysAddr::from_raw(region.end);

        if end.as_raw() <= start.as_raw() {
            continue;
        }

        let aligned_start = start.align_up(align);
        if aligned_start.as_raw() >= end.as_raw() {
            continue;
        }

        let size_u64 = end.as_raw() - aligned_start.as_raw();
        let mut size = usize::try_from(size_u64).map_err(|_| MemoryError::AddressOverflow)?;
        // Round size down to page multiple
        size -= size % align;
        if size == 0 {
            continue;
        }

        let phys_start =
            usize::try_from(aligned_start.as_raw()).map_err(|_| MemoryError::AddressOverflow)?;
        let virt_start_raw = phys_start
            .checked_add(offset_usize)
            .ok_or(MemoryError::AddressOverflow)?;
        let virt_start = VirtAddr::from_raw(virt_start_raw);

        if let Some((_, current_size)) = best {
            if current_size >= size {
                continue;
            }
        }
        best = Some((virt_start, size));
    }

    let (virt_start, size) = best.ok_or(MemoryError::NoUsableRegion)?;
    HeapRegion::new(virt_start, size).map_err(MemoryError::Region)
}
