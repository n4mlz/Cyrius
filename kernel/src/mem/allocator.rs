use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{NonNull, null_mut};
use core::sync::atomic::{AtomicBool, Ordering};

use linked_list_allocator::Heap;

use crate::mem::addr::{Addr, PageSize, VirtAddr, VirtIntoPtr};
use crate::util::spinlock::SpinLock;

#[derive(Clone, Copy, Debug)]
pub struct HeapRegion {
    start: VirtAddr,
    size: usize,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HeapRegionError {
    Empty,
    Misaligned { align: usize },
    Overflow,
}

impl HeapRegion {
    pub const fn size(&self) -> usize {
        self.size
    }

    pub const fn start(&self) -> VirtAddr {
        self.start
    }

    pub fn new(start: VirtAddr, size: usize) -> Result<Self, HeapRegionError> {
        if size == 0 {
            return Err(HeapRegionError::Empty);
        }

        // Align heap to page boundary (4 KiB)
        let align = PageSize::SIZE_4K.bytes();
        if !start.is_aligned(align) {
            return Err(HeapRegionError::Misaligned { align });
        }

        if start.checked_add(size).is_none() {
            return Err(HeapRegionError::Overflow);
        }

        Ok(Self { start, size })
    }
}

#[derive(Debug)]
pub enum MemoryError {
    MissingPhysicalMapping,
    NoUsableRegion,
    AddressOverflow,
    Region(HeapRegionError),
}

#[derive(Debug)]
pub enum AllocatorInitError {
    AlreadyInitialized,
}

pub type AllocatorInitResult = Result<(), AllocatorInitError>;

pub fn init(region: HeapRegion) -> AllocatorInitResult {
    unsafe { GLOBAL_ALLOCATOR.init(region) }
}

struct KernelAllocator {
    heap: SpinLock<Heap>,
    initialized: AtomicBool,
}

impl KernelAllocator {
    pub const fn new() -> Self {
        Self {
            heap: SpinLock::new(Heap::empty()),
            initialized: AtomicBool::new(false),
        }
    }

    unsafe fn init(&self, region: HeapRegion) -> AllocatorInitResult {
        if self.initialized.load(Ordering::Acquire) {
            return Err(AllocatorInitError::AlreadyInitialized);
        }

        {
            let mut heap = self.heap.lock();
            if self.initialized.load(Ordering::Relaxed) {
                return Err(AllocatorInitError::AlreadyInitialized);
            }
            unsafe { heap.init(region.start().into_mut_ptr(), region.size()) };
        }

        self.initialized.store(true, Ordering::Release);
        Ok(())
    }

    fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }
}

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !self.is_initialized() {
            return null_mut();
        }

        let mut heap = self.heap.lock();
        match heap.allocate_first_fit(layout) {
            Ok(block) => block.as_ptr().cast::<u8>(),
            Err(_) => null_mut(),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if !self.is_initialized() {
            return;
        }

        if let Some(non_null) = NonNull::new(ptr) {
            let mut heap = self.heap.lock();
            unsafe { heap.deallocate(non_null, layout) };
        }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: KernelAllocator = KernelAllocator::new();

#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    panic!("allocation error: {:?}", layout);
}
