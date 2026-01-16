pub mod address_space;
pub mod paging;

use core::convert::TryFrom;

use bootloader_api::{BootInfo, info::MemoryRegionKind};

use crate::arch::api::HeapRegionError;
use crate::mem::addr::{AddrRange, VirtAddr, align_down_u64, align_up_u64};

const PAGE_SIZE: u64 = 4096;

pub fn locate_kernel_heap(
    boot_info: &'static BootInfo,
) -> Result<AddrRange<VirtAddr>, HeapRegionError> {
    let phys_offset = boot_info
        .physical_memory_offset
        .as_ref()
        .copied()
        .ok_or(HeapRegionError::MissingPhysicalMapping)?;

    let mut best: Option<(u64, u64)> = None;

    for region in boot_info.memory_regions.iter() {
        if region.kind != MemoryRegionKind::Usable {
            continue;
        }

        let start = match align_up_u64(region.start, PAGE_SIZE) {
            Some(addr) => addr,
            None => continue,
        };
        let end = align_down_u64(region.end, PAGE_SIZE);

        if end <= start {
            continue;
        }

        match best {
            Some((_, best_len)) if best_len >= end - start => {}
            _ => best = Some((start, end - start)),
        }
    }

    let (phys_start, len) = best.ok_or(HeapRegionError::NoUsableRegion)?;
    let phys_end = phys_start
        .checked_add(len)
        .ok_or(HeapRegionError::AddressOverflow)?;

    let virt_start = phys_start
        .checked_add(phys_offset)
        .ok_or(HeapRegionError::AddressOverflow)?;
    let virt_end = phys_end
        .checked_add(phys_offset)
        .ok_or(HeapRegionError::AddressOverflow)?;

    let start = usize::try_from(virt_start).map_err(|_| HeapRegionError::AddressOverflow)?;
    let end = usize::try_from(virt_end).map_err(|_| HeapRegionError::AddressOverflow)?;

    Ok(AddrRange {
        start: VirtAddr::new(start),
        end: VirtAddr::new(end),
    })
}
