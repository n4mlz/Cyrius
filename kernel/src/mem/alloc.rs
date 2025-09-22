use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self, NonNull};

use crate::mem::addr::{Addr, AddrRange, VirtAddr};
use crate::util::spinlock::SpinLock;

const DEFAULT_HEAP_SIZE: usize = 1024 * 1024; // 1 MiB

static mut HEAP_SPACE: [u8; DEFAULT_HEAP_SIZE] = [0; DEFAULT_HEAP_SIZE];

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

fn align_up(addr: usize, align: usize) -> Option<usize> {
    debug_assert!(align.is_power_of_two());
    let mask = align - 1;
    let sum = addr.checked_add(mask)?;
    Some(sum & !mask)
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

pub fn init_default_heap() {
    unsafe {
        let start_ptr = ptr::addr_of_mut!(HEAP_SPACE) as *mut u8;
        let start = VirtAddr::from_ptr(start_ptr);
        let end = VirtAddr::from_ptr(start_ptr.add(DEFAULT_HEAP_SIZE));
        init_heap(AddrRange { start, end });
    }
}

pub fn init_heap(range: AddrRange<VirtAddr>) {
    assert!(
        range.end.as_usize() > range.start.as_usize(),
        "heap range must be non-empty"
    );
    let mut guard = ALLOCATOR.lock();
    unsafe {
        guard.init(range);
    }
}

pub fn heap_stats() -> Option<HeapStats> {
    let guard = ALLOCATOR.lock();
    guard.stats()
}

#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    panic!("allocation failed: {:?}", layout);
}
