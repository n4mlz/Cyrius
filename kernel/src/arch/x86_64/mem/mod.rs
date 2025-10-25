pub mod address_space;
pub mod paging;

use core::convert::TryFrom;

use bootloader_api::{BootInfo, info::MemoryRegionKind};

use crate::arch::api::HeapRegionError;
use crate::mem::addr::{AddrRange, VirtAddr};

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

        let start = match align_up(region.start, PAGE_SIZE) {
            Some(addr) => addr,
            None => continue,
        };
        let end = align_down(region.end, PAGE_SIZE);

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

fn align_up(value: u64, align: u64) -> Option<u64> {
    debug_assert!(align.is_power_of_two());
    let mask = align - 1;
    if value & mask == 0 {
        Some(value)
    } else {
        let delta = align - (value & mask);
        value.checked_add(delta)
    }
}

fn align_down(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    value & !(align - 1)
}
