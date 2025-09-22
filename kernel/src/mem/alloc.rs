use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self, NonNull};

use crate::arch::{Arch, api::ArchPlatform};
use crate::boot::{BootInfo, MemoryMap, PhysicalRegionKind};
use crate::mem::addr::{Addr, AddrRange, PhysAddr, VirtAddr};
use crate::util::align_up;
use crate::util::spinlock::SpinLock;

const HEAP_ALIGNMENT: usize = 0x1000;

#[derive(Copy, Clone, Debug)]
pub struct HeapStats {
    pub start: VirtAddr,
    pub end: VirtAddr,
    pub next: VirtAddr,
}

struct BumpAllocator {
    start: usize,
    end: usize,
    next: usize,
    initialized: bool,
}

impl BumpAllocator {
    const fn new() -> Self {
        Self {
            start: 0,
            end: 0,
            next: 0,
            initialized: false,
        }
    }

    unsafe fn init(&mut self, range: AddrRange<VirtAddr>) {
        if self.initialized {
            panic!("BumpAllocator reinitialized");
        }

        self.start = range.start.as_usize();
        self.end = range.end.as_usize();
        self.next = self.start;
        self.initialized = true;
    }

    fn allocate(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        if !self.initialized {
            return None;
        }

        let size = layout.size().max(1);
        let aligned = align_up(self.next, layout.align())?;
        let new_next = aligned.checked_add(size)?;

        if new_next > self.end {
            return None;
        }

        self.next = new_next;
        let ptr = aligned as *mut u8;
        NonNull::new(ptr)
    }

    unsafe fn deallocate(&mut self, _ptr: *mut u8, _layout: Layout) {
        // bump allocator does not support free
    }

    fn stats(&self) -> Option<HeapStats> {
        if !self.initialized {
            return None;
        }

        Some(HeapStats {
            start: VirtAddr::from_usize(self.start),
            end: VirtAddr::from_usize(self.end),
            next: VirtAddr::from_usize(self.next),
        })
    }
}

struct KernelAllocator;

static ALLOCATOR: SpinLock<BumpAllocator> = SpinLock::new(BumpAllocator::new());

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut guard = ALLOCATOR.lock();
        guard
            .allocate(layout)
            .map(NonNull::as_ptr)
            .unwrap_or(ptr::null_mut())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut guard = ALLOCATOR.lock();
        unsafe {
            guard.deallocate(ptr, layout);
        }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: KernelAllocator = KernelAllocator;

pub struct KernelHeap;

impl KernelHeap {
    pub fn init(boot_info: &BootInfo<<Arch as ArchPlatform>::ArchBootInfo>) {
        let phys_range = Self::select_region(boot_info.memory_map);
        let virt_range =
            Arch::map_kernel_heap(boot_info, phys_range).expect("failed to map kernel heap");
        Self::install(virt_range);
    }

    pub fn stats() -> Option<HeapStats> {
        let guard = ALLOCATOR.lock();
        guard.stats()
    }

    // Selects a suitable physical memory region for the kernel heap.
    fn select_region(map: MemoryMap<'_>) -> AddrRange<PhysAddr> {
        debug_assert!(HEAP_ALIGNMENT.is_power_of_two());

        map.iter()
            .filter(|region| region.kind == PhysicalRegionKind::Usable)
            .filter_map(|region| {
                let aligned_start = region.range.start.align_up(HEAP_ALIGNMENT);
                let region_end = region.range.end.as_usize();
                let start = aligned_start.as_usize();
                if start >= region_end {
                    return None;
                }

                let available = region_end - start;
                let usable = available & !(HEAP_ALIGNMENT - 1);
                if usable == 0 {
                    return None;
                }

                let end = start.checked_add(usable)?;

                Some((
                    usable,
                    AddrRange {
                        start: aligned_start,
                        end: PhysAddr::from_usize(end),
                    },
                ))
            })
            .max_by_key(|(usable, _)| *usable)
            .map(|(_, range)| range)
            .expect("no suitable usable memory region found for heap")
    }

    fn install(range: AddrRange<VirtAddr>) {
        assert!(
            range.end.as_usize() > range.start.as_usize(),
            "heap range must be non-empty"
        );

        let mut guard = ALLOCATOR.lock();
        unsafe {
            guard.init(range);
        }
    }
}

#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    panic!("allocation failed: {:?}", layout);
}
