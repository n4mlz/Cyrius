//! Physical frame allocation backed by the bootloader memory map.

use alloc::vec::Vec;
use core::convert::TryFrom;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

use bootloader_api::BootInfo;
use bootloader_api::info::{MemoryRegion, MemoryRegionKind};

use crate::mem::addr::{Addr, AddrRange, Page, PageSize, PhysAddr};
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

        let start = align_up(region.start, FRAME_SIZE)?;
        let end = align_down(region.end, FRAME_SIZE);

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
        if let Some(aligned) = align_up(self.next, FRAME_SIZE) {
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

    pub fn reserve(&mut self, range: AddrRange<PhysAddr>) {
        if range.is_empty() {
            return;
        }

        let start = align_down(range.start.as_raw() as u64, FRAME_SIZE);
        let end =
            align_up(range.end.as_raw() as u64, FRAME_SIZE).expect("reserved range end overflow");

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
            if let Some(last) = merged.last_mut() {
                if range.start.as_raw() <= last.end.as_raw() {
                    if range.end.as_raw() > last.end.as_raw() {
                        last.end = range.end;
                    }
                    continue;
                }
            }
            merged.push(range);
        }

        self.reserved = merged;
    }

    fn allocate_from_current(&mut self) -> Option<Page<PhysAddr>> {
        loop {
            let phys = {
                let cursor = match self.current.as_mut() {
                    Some(cursor) => cursor,
                    None => return None,
                };

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

    fn reserved_overlap(&self, start: u64, end: u64) -> Option<u64> {
        for range in &self.reserved {
            let r_start = range.start.as_raw() as u64;
            let r_end = range.end.as_raw() as u64;
            if start < r_end && end > r_start {
                return align_up(r_end, FRAME_SIZE);
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

fn align_up(value: u64, align: u64) -> Option<u64> {
    debug_assert!(align.is_power_of_two());
    let mask = align - 1;
    if value & mask == 0 {
        Some(value)
    } else {
        value.checked_add(align - (value & mask))
    }
}

fn align_down(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    value & !(align - 1)
}

pub struct FrameAllocatorGuard<'a> {
    guard: SpinLockGuard<'a, MaybeUninit<BootInfoFrameAllocator>>,
}

impl<'a> core::ops::Deref for FrameAllocatorGuard<'a> {
    type Target = BootInfoFrameAllocator;

    fn deref(&self) -> &Self::Target {
        unsafe { (&*self.guard).assume_init_ref() }
    }
}

impl<'a> core::ops::DerefMut for FrameAllocatorGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { (&mut *self.guard).assume_init_mut() }
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
    use crate::test::kernel_test_case;
    use alloc::vec;
    use bootloader_api::info::{MemoryRegion, MemoryRegionKind};

    const fn region(start: u64, end: u64, kind: MemoryRegionKind) -> MemoryRegion {
        MemoryRegion { start, end, kind }
    }

    #[kernel_test_case]
    fn reserve_excludes_frames() {
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
}
