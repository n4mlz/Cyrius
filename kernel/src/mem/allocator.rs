use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicBool, Ordering};

use buddy_system_allocator::LockedHeap as BuddyLockedHeap;

use crate::mem::addr::{AddrRange, VirtAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapInitError {
    AlreadyInitialized,
    InvalidRange,
    EmptyRange,
}

pub struct LockedHeap {
    heap: BuddyLockedHeap<32>,
    initialised: AtomicBool,
}

impl LockedHeap {
    pub const fn new() -> Self {
        Self {
            heap: BuddyLockedHeap::empty(),
            initialised: AtomicBool::new(false),
        }
    }

    pub fn init(&self, range: AddrRange<VirtAddr>) -> Result<(), HeapInitError> {
        let len = range.len_checked().ok_or(HeapInitError::InvalidRange)?;

        if len == 0 {
            return Err(HeapInitError::EmptyRange);
        }

        self.initialise_inner(range.start, len)
    }

    fn initialise_inner(&self, start: VirtAddr, len: usize) -> Result<(), HeapInitError> {
        self.initialised
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| HeapInitError::AlreadyInitialized)?;

        unsafe { self.heap.lock().init(start.as_raw(), len) };

        Ok(())
    }

    pub fn is_initialised(&self) -> bool {
        self.initialised.load(Ordering::Acquire)
    }
}

impl Default for LockedHeap {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl GlobalAlloc for LockedHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { GlobalAlloc::alloc(&self.heap, layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { GlobalAlloc::dealloc(&self.heap, ptr, layout) };
    }
}

#[global_allocator]
static KERNEL_HEAP: LockedHeap = LockedHeap::new();

/// Initialise the global heap allocator.
///
/// # Safety Contract
///
/// The provided memory range must already be mapped into the kernel's address
/// space with read/write permissions and remain exclusively owned by the heap.
/// Call this function exactly once during boot before using types from the
/// `alloc` crate.
pub fn init_heap(range: AddrRange<VirtAddr>) -> Result<(), HeapInitError> {
    KERNEL_HEAP.init(range)
}

pub fn is_initialised() -> bool {
    KERNEL_HEAP.is_initialised()
}

#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    panic!("allocation error: {layout:?}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{println, test::kernel_test_case};

    const HEAP_BYTES: usize = 64 * 1024;

    #[repr(align(4096))]
    struct TestRegion([u8; HEAP_BYTES]);

    static mut TEST_REGION: TestRegion = TestRegion([0; HEAP_BYTES]);

    fn test_range() -> AddrRange<VirtAddr> {
        let start = region_base() as usize;
        let end = start + HEAP_BYTES;
        AddrRange {
            start: VirtAddr::new(start),
            end: VirtAddr::new(end),
        }
    }

    fn region_base() -> *mut u8 {
        unsafe { core::ptr::addr_of_mut!(TEST_REGION.0) as *mut u8 }
    }

    unsafe fn reset_region() {
        unsafe { core::ptr::write_bytes(region_base(), 0, HEAP_BYTES) };
    }

    #[kernel_test_case]
    fn initialise_and_allocate() {
        println!("[test] initialise_and_allocate");

        unsafe { reset_region() };

        let heap = LockedHeap::new();
        let range = test_range();

        heap.init(range).expect("heap init");
        assert!(heap.is_initialised());

        let layout = Layout::from_size_align(256, 16).expect("layout");
        let ptr = unsafe { heap.alloc(layout) };
        assert!(!ptr.is_null(), "allocation returned null");

        unsafe {
            core::ptr::write_bytes(ptr, 0xAA, layout.size());
            heap.dealloc(ptr, layout);
        }

        let second = unsafe { heap.alloc(layout) };
        assert!(!second.is_null(), "second allocation failed");
        unsafe {
            heap.dealloc(second, layout);
        }
    }

    #[kernel_test_case]
    fn double_initialisation_fails() {
        println!("[test] double_initialisation_fails");

        unsafe { reset_region() };

        let heap = LockedHeap::new();
        let range = test_range();

        heap.init(range).expect("first init");
        let err = heap.init(range).expect_err("second init should fail");
        assert_eq!(err, HeapInitError::AlreadyInitialized);
    }
}
