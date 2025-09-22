use crate::boot::{BootInfo, MemoryMap, PhysicalRegionKind};
use crate::mem::addr::{Addr, AddrRange, Page, PageSize, PhysAddr};

pub trait FrameAllocator {
    fn alloc(&mut self, size: PageSize) -> Option<Page<PhysAddr>>;
    fn free(&mut self, page: Page<PhysAddr>);
}

pub struct BootFrameAllocator<'a> {
    regions: &'a [crate::boot::PhysicalRegion],
    region_idx: usize,
    next: PhysAddr,
    reserved: Option<AddrRange<PhysAddr>>,
}

impl<'a> BootFrameAllocator<'a> {
    pub fn new(map: MemoryMap<'a>) -> Self {
        let mut allocator = Self {
            regions: map.regions(),
            region_idx: 0,
            next: PhysAddr::NULL,
            reserved: None,
        };
        allocator.advance_region();
        allocator
    }

    pub fn from_boot_info<ArchData>(boot_info: &BootInfo<ArchData>) -> Self {
        Self::new(boot_info.memory_map)
    }

    pub fn with_reservation(map: MemoryMap<'a>, reserved: AddrRange<PhysAddr>) -> Self {
        let mut allocator = Self {
            regions: map.regions(),
            region_idx: 0,
            next: PhysAddr::NULL,
            reserved: Some(reserved),
        };
        allocator.advance_region();
        allocator
    }

    pub fn with_reservation_from_boot_info<ArchData>(
        boot_info: &BootInfo<ArchData>,
        reserved: AddrRange<PhysAddr>,
    ) -> Self {
        Self::with_reservation(boot_info.memory_map, reserved)
    }

    fn advance_region(&mut self) {
        while self.region_idx < self.regions.len() {
            let region = &self.regions[self.region_idx];
            if region.kind == PhysicalRegionKind::Usable && !region.range.is_empty() {
                self.next = region.range.start;
                return;
            }
            self.region_idx += 1;
        }
        self.next = PhysAddr::NULL;
    }
}

impl<'a> FrameAllocator for BootFrameAllocator<'a> {
    fn alloc(&mut self, size: PageSize) -> Option<Page<PhysAddr>> {
        let page_bytes = size.bytes();

        while self.region_idx < self.regions.len() {
            let region = &self.regions[self.region_idx];
            if region.kind != PhysicalRegionKind::Usable || region.range.is_empty() {
                self.region_idx += 1;
                self.advance_region();
                continue;
            }

            let candidate = self.next.align_up(page_bytes);
            let candidate_addr = candidate.as_usize();
            let candidate_end = candidate_addr.checked_add(page_bytes)?;

            if let Some(reserved) = self.reserved {
                let reserved_start = reserved.start.as_usize();
                let reserved_end = reserved.end.as_usize();
                if candidate_addr < reserved_end && candidate_end > reserved_start {
                    self.next = PhysAddr::from_usize(reserved_end);
                    continue;
                }
            }

            if candidate_end <= region.range.end.as_usize() {
                self.next = PhysAddr::from_usize(candidate_end);
                return Some(Page::new(candidate, size));
            }

            self.region_idx += 1;
            self.advance_region();
        }

        None
    }

    fn free(&mut self, _page: Page<PhysAddr>) {
        panic!("BootFrameAllocator does not support free");
    }
}
