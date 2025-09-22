use crate::boot::{BootInfo, MemoryMap, PhysicalRegionKind};
use crate::mem::addr::{Addr, Page, PageSize, PhysAddr};

pub trait FrameAllocator {
    fn alloc(&mut self, size: PageSize) -> Option<Page<PhysAddr>>;
    fn free(&mut self, page: Page<PhysAddr>);
}

pub struct BootFrameAllocator<'a> {
    regions: &'a [crate::boot::PhysicalRegion],
    region_idx: usize,
    next: PhysAddr,
}

impl<'a> BootFrameAllocator<'a> {
    pub fn new(map: MemoryMap<'a>) -> Self {
        let mut allocator = Self {
            regions: map.regions(),
            region_idx: 0,
            next: PhysAddr::NULL,
        };
        allocator.advance_region();
        allocator
    }

    pub fn from_boot_info<ArchData>(boot_info: &BootInfo<ArchData>) -> Self {
        Self::new(boot_info.memory_map)
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
            let candidate_end = candidate.as_usize().checked_add(page_bytes)?;
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
