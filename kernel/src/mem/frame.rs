//! Physical frame allocation backed by the bootloader memory map.

use alloc::vec::Vec;
use core::convert::TryFrom;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

use bootloader_api::BootInfo;
use bootloader_api::info::{MemoryRegion, MemoryRegionKind};

use crate::mem::addr::{
    Addr, AddrRange, Page, PageSize, PhysAddr, align_down_u64, align_up_u64,
};
use crate::mem::paging::FrameAllocator;
use crate::util::spinlock::{SpinLock, SpinLockGuard};

const FRAME_SIZE: u64 = 4096;

/// Cursor that tracks allocation progress within a usable memory region.
#[derive(Debug, Clone)]
struct RegionCursor {
    _start: u64,
    end: u64,
    next: u64,
}

impl RegionCursor {
    fn new(region: &MemoryRegion) -> Option<Self> {
        if region.kind != MemoryRegionKind::Usable {
            return None;
        }

        // Skip regions starting at address 0 to avoid NULL pointer issues
        if region.start == 0 {
            return None;
        }

        let start = align_up_u64(region.start, FRAME_SIZE)?;
        let end = align_down_u64(region.end, FRAME_SIZE);

        if end <= start {
            return None;
        }

        Some(Self {
            _start: start,
            end,
            next: start,
        })
    }

    fn exhausted(&self) -> bool {
        self.next >= self.end
    }

    fn align_next(&mut self) {
        if let Some(aligned) = align_up_u64(self.next, FRAME_SIZE) {
            self.next = aligned;
        }
    }

    fn allocate(&mut self) -> Option<PhysAddr> {
        self.align_next();
        if self.exhausted() {
            return None;
        }

        let frame_start = self.next;
        self.next = self
            .next
            .checked_add(FRAME_SIZE)
            .expect("frame allocation pointer overflow");
        Some(PhysAddr::new(
            usize::try_from(frame_start).expect("frame start exceeds usize"),
        ))
    }

    fn skip_to(&mut self, addr: u64) {
        self.next = addr;
    }
}

#[derive(Debug)]
pub struct BootInfoFrameAllocator {
    regions: &'static [MemoryRegion],
    region_index: usize,
    current: Option<RegionCursor>,
    recycled: Vec<Page<PhysAddr>>,
    reserved: Vec<AddrRange<PhysAddr>>,
}

impl BootInfoFrameAllocator {
    pub fn new(regions: &'static [MemoryRegion]) -> Self {
        Self {
            regions,
            region_index: 0,
            current: None,
            recycled: Vec::new(),
            reserved: Vec::new(),
        }
    }

    pub fn allocate_contiguous(
        &mut self,
        count: usize,
        size: PageSize,
    ) -> Option<Vec<Page<PhysAddr>>> {
        if size != PageSize::SIZE_4K || count == 0 {
            return None;
        }
        if let Some(run) = self.take_recycled_run(count) {
            return Some(run);
        }
        self.allocate_run(count)
    }

    pub fn reserve(&mut self, range: AddrRange<PhysAddr>) {
        if range.is_empty() {
            return;
        }

        let start = align_down_u64(range.start.as_raw() as u64, FRAME_SIZE);
        let end = align_up_u64(range.end.as_raw() as u64, FRAME_SIZE)
            .expect("reserved range end overflow");

        if end <= start {
            return;
        }

        let start = usize::try_from(start).expect("reserved range start exceeds usize");
        let end = usize::try_from(end).expect("reserved range end exceeds usize");

        self.reserved.push(AddrRange {
            start: PhysAddr::new(start),
            end: PhysAddr::new(end),
        });
        self.normalise_reserved();
    }

    fn normalise_reserved(&mut self) {
        if self.reserved.is_empty() {
            return;
        }

        self.reserved.sort_by_key(|range| range.start.as_raw());

        let mut merged: Vec<AddrRange<PhysAddr>> = Vec::with_capacity(self.reserved.len());

        for range in self.reserved.drain(..) {
            if let Some(last) = merged.last_mut()
                && range.start.as_raw() <= last.end.as_raw()
            {
                if range.end.as_raw() > last.end.as_raw() {
                    last.end = range.end;
                }
                continue;
            }
            merged.push(range);
        }

        self.reserved = merged;
    }

    fn allocate_from_current(&mut self) -> Option<Page<PhysAddr>> {
        loop {
            let phys = {
                let cursor = self.current.as_mut()?;

                if cursor.exhausted() {
                    self.current = None;
                    continue;
                }

                match cursor.allocate() {
                    Some(phys) => phys,
                    None => {
                        self.current = None;
                        continue;
                    }
                }
            };

            let frame_end = phys
                .checked_add(PageSize::SIZE_4K.bytes())
                .expect("frame end overflow");

            if let Some(skip_to) =
                self.reserved_overlap(phys.as_raw() as u64, frame_end.as_raw() as u64)
            {
                if let Some(cursor) = self.current.as_mut() {
                    cursor.skip_to(skip_to);
                }
                continue;
            }

            return Some(Page::new(phys, PageSize::SIZE_4K));
        }
    }

    fn take_recycled_run(&mut self, count: usize) -> Option<Vec<Page<PhysAddr>>> {
        if self.recycled.len() < count {
            return None;
        }

        // Prefer fulfilling contiguous requests from recycled frames to avoid exhausting
        // the underlying allocator during short-lived DMA transfers.
        self.recycled.sort_by_key(|page| page.start.as_raw());

        let mut run_start = 0usize;
        let mut run_len = 0usize;
        let mut prev_addr: Option<usize> = None;

        for (idx, page) in self.recycled.iter().enumerate() {
            let addr = page.start.as_raw();
            match prev_addr {
                Some(prev) if addr == prev + FRAME_SIZE as usize => {
                    run_len += 1;
                }
                _ => {
                    run_start = idx;
                    run_len = 1;
                }
            }
            prev_addr = Some(addr);

            if run_len == count {
                return Some(self.recycled.drain(run_start..run_start + count).collect());
            }
        }

        None
    }

    fn allocate_run(&mut self, count: usize) -> Option<Vec<Page<PhysAddr>>> {
        loop {
            if self.current.is_none() && !self.advance_region() {
                return None;
            }

            let mut reset_region = false;
            let (start, end) = {
                let cursor = self
                    .current
                    .as_mut()
                    .expect("cursor must exist after advance_region");
                cursor.align_next();
                let start = cursor.next;
                let bytes = FRAME_SIZE.checked_mul(count as u64)?;
                let end = start.checked_add(bytes)?;
                if end > cursor.end {
                    reset_region = true;
                }
                (start, end)
            };

            if reset_region {
                self.current = None;
                continue;
            }

            if let Some(skip_to) = self.reserved_overlap(start, end) {
                if let Some(cursor) = self.current.as_mut() {
                    cursor.skip_to(skip_to);
                }
                continue;
            }

            if let Some(cursor) = self.current.as_mut() {
                cursor.next = end;
            }
            return Some(build_page_run(start, count));
        }
    }

    fn reserved_overlap(&self, start: u64, end: u64) -> Option<u64> {
        for range in &self.reserved {
            let r_start = range.start.as_raw() as u64;
            let r_end = range.end.as_raw() as u64;
            if start < r_end && end > r_start {
                return align_up_u64(r_end, FRAME_SIZE);
            }
        }
        None
    }

    fn advance_region(&mut self) -> bool {
        while self.region_index < self.regions.len() {
            let region = &self.regions[self.region_index];
            self.region_index += 1;
            if let Some(cursor) = RegionCursor::new(region) {
                self.current = Some(cursor);
                return true;
            }
        }
        false
    }
}

impl FrameAllocator for BootInfoFrameAllocator {
    fn allocate(&mut self, size: PageSize) -> Option<Page<PhysAddr>> {
        if size != PageSize::SIZE_4K {
            return None;
        }

        if let Some(frame) = self.recycled.pop() {
            return Some(frame);
        }

        loop {
            if let Some(frame) = self.allocate_from_current() {
                return Some(frame);
            }
            if !self.advance_region() {
                return None;
            }
        }
    }

    fn deallocate(&mut self, frame: Page<PhysAddr>) {
        self.recycled.push(frame);
    }
}

fn build_page_run(start: u64, count: usize) -> Vec<Page<PhysAddr>> {
    let mut frames = Vec::with_capacity(count);
    for index in 0..count {
        let addr = start
            .checked_add(FRAME_SIZE * index as u64)
            .expect("contiguous run overflow");
        let phys =
            PhysAddr::new(usize::try_from(addr).expect("contiguous run address exceeds usize"));
        frames.push(Page::new(phys, PageSize::SIZE_4K));
    }
    frames
}

pub struct FrameAllocatorGuard<'a> {
    guard: SpinLockGuard<'a, MaybeUninit<BootInfoFrameAllocator>>,
}

impl<'a> core::ops::Deref for FrameAllocatorGuard<'a> {
    type Target = BootInfoFrameAllocator;

    fn deref(&self) -> &Self::Target {
        unsafe { (*self.guard).assume_init_ref() }
    }
}

impl<'a> core::ops::DerefMut for FrameAllocatorGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { (*self.guard).assume_init_mut() }
    }
}

impl<'a> FrameAllocatorGuard<'a> {
    pub fn allocate_contiguous(
        &mut self,
        count: usize,
        size: PageSize,
    ) -> Option<Vec<Page<PhysAddr>>> {
        (**self).allocate_contiguous(count, size)
    }
}

impl<'a> FrameAllocator for FrameAllocatorGuard<'a> {
    fn allocate(&mut self, size: PageSize) -> Option<Page<PhysAddr>> {
        (**self).allocate(size)
    }

    fn deallocate(&mut self, frame: Page<PhysAddr>) {
        (**self).deallocate(frame);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameAllocatorInitError {
    AlreadyInitialised,
}

pub struct GlobalFrameAllocator {
    inner: SpinLock<MaybeUninit<BootInfoFrameAllocator>>,
    initialised: AtomicBool,
}

impl GlobalFrameAllocator {
    pub const fn uninit() -> Self {
        Self {
            inner: SpinLock::new(MaybeUninit::uninit()),
            initialised: AtomicBool::new(false),
        }
    }

    pub fn init(
        &self,
        boot_info: &'static BootInfo,
        reserved: &[AddrRange<PhysAddr>],
    ) -> Result<(), FrameAllocatorInitError> {
        if self.initialised.load(Ordering::Acquire) {
            return Err(FrameAllocatorInitError::AlreadyInitialised);
        }

        let regions: &'static [MemoryRegion] = &boot_info.memory_regions;
        let mut allocator = BootInfoFrameAllocator::new(regions);
        for range in reserved {
            allocator.reserve(*range);
        }

        let mut guard = self.inner.lock();
        if self.initialised.load(Ordering::Acquire) {
            return Err(FrameAllocatorInitError::AlreadyInitialised);
        }
        guard.write(allocator);
        drop(guard);

        self.initialised.store(true, Ordering::Release);
        Ok(())
    }

    pub fn lock(&self) -> FrameAllocatorGuard<'_> {
        assert!(
            self.initialised.load(Ordering::Acquire),
            "frame allocator not initialised"
        );
        FrameAllocatorGuard {
            guard: self.inner.lock(),
        }
    }
}

pub static FRAME_ALLOCATOR: GlobalFrameAllocator = GlobalFrameAllocator::uninit();

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{println, test::kernel_test_case};
    use bootloader_api::info::{MemoryRegion, MemoryRegionKind};

    const fn region(start: u64, end: u64, kind: MemoryRegionKind) -> MemoryRegion {
        MemoryRegion { start, end, kind }
    }

    #[kernel_test_case]
    fn reserve_excludes_frames() {
        println!("[test] reserve_excludes_frames");

        static REGIONS: [MemoryRegion; 1] = [region(0x1000, 0x9000, MemoryRegionKind::Usable)];
        let mut allocator = BootInfoFrameAllocator::new(&REGIONS);

        let reserved = AddrRange {
            start: PhysAddr::new(0x3000),
            end: PhysAddr::new(0x5000),
        };
        allocator.reserve(reserved);

        let mut frames = Vec::new();
        for _ in 0..4 {
            if let Some(frame) = allocator.allocate(PageSize::SIZE_4K) {
                frames.push(frame.start.as_raw());
            }
        }

        assert_eq!(frames.len(), 4);
        assert_eq!(frames[0], 0x1000);
        assert_eq!(frames[1], 0x2000);
        assert!(frames.iter().all(|addr| *addr != 0x3000 && *addr != 0x4000));
        assert!(frames[2] >= 0x5000);
    }

    #[kernel_test_case]
    fn recycle_returns_frames() {
        println!("[test] recycle_returns_frames");

        static REGIONS: [MemoryRegion; 1] = [region(0x1000, 0x3000, MemoryRegionKind::Usable)];
        let mut allocator = BootInfoFrameAllocator::new(&REGIONS);

        let frame = allocator
            .allocate(PageSize::SIZE_4K)
            .expect("allocation should succeed");
        allocator.deallocate(frame);

        let recycled = allocator
            .allocate(PageSize::SIZE_4K)
            .expect("recycled frame should be available");
        assert_eq!(recycled.start.as_raw(), 0x1000);
    }

    #[kernel_test_case]
    fn contiguous_allocation_reuses_recycled_runs() {
        println!("[test] contiguous_allocation_reuses_recycled_runs");

        static REGIONS: [MemoryRegion; 1] = [region(0x1000, 0x9000, MemoryRegionKind::Usable)];
        let mut allocator = BootInfoFrameAllocator::new(&REGIONS);

        let run = allocator
            .allocate_contiguous(2, PageSize::SIZE_4K)
            .expect("initial contiguous allocation");
        let expected: Vec<_> = run.iter().map(|page| page.start.as_raw()).collect();
        for frame in run {
            allocator.deallocate(frame);
        }

        let recycled = allocator
            .allocate_contiguous(2, PageSize::SIZE_4K)
            .expect("recycled contiguous allocation");
        let observed: Vec<_> = recycled.iter().map(|page| page.start.as_raw()).collect();
        assert_eq!(observed, expected);
    }
}
