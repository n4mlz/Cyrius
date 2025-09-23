use core::alloc::{GlobalAlloc, Layout};
use core::ptr::{self, NonNull};

use crate::arch::{Arch, api::ArchPlatform};
use crate::boot::BootInfo;
use crate::mem::addr::{Addr, AddrRange, PhysAddr, VirtAddr};
use crate::mem::planner::KernelMemoryPlanner;
use crate::util::align_up;
use crate::util::spinlock::SpinLock;

#[derive(Copy, Clone, Debug)]
pub struct HeapStats {
    pub phys: AddrRange<PhysAddr>,
    pub virt: AddrRange<VirtAddr>,
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

    unsafe fn dealloc(&mut self, _ptr: *mut u8, _layout: Layout) {
        // bump allocator does not support free
    }

    fn cursor(&self) -> Option<VirtAddr> {
        if !self.initialized {
            return None;
        }

        Some(VirtAddr::from_usize(self.next))
    }

    fn is_initialized(&self) -> bool {
        self.initialized
    }
}

pub struct KernelHeap {
    allocator: SpinLock<BumpAllocator>,
    mapping: SpinLock<Option<HeapMapping>>,
}

#[derive(Copy, Clone, Debug)]
struct HeapMapping {
    phys: AddrRange<PhysAddr>,
    virt: AddrRange<VirtAddr>,
}

impl KernelHeap {
    pub const fn new() -> Self {
        Self {
            allocator: SpinLock::new(BumpAllocator::new()),
            mapping: SpinLock::new(None),
        }
    }

    pub fn global() -> &'static Self {
        &GLOBAL_ALLOCATOR
    }

    pub fn init(&self, _boot_info: &BootInfo<<Arch as ArchPlatform>::ArchBootInfo>) {
        if self.mapping.lock().is_some() {
            return;
        }

        let planner = KernelMemoryPlanner::global();
        let phys_range = planner
            .heap_phys()
            .expect("kernel heap physical range unavailable");
        let layout = planner.layout().expect("kernel memory layout unavailable");
        self.apply_layout(phys_range, layout.heap);
    }

    pub fn stats(&self) -> Option<HeapStats> {
        let mapping = *self.mapping.lock();
        let mapping = mapping?;

        let guard = self.allocator.lock();
        if !guard.is_initialized() {
            return None;
        }

        let next = guard.cursor()?;

        Some(HeapStats {
            phys: mapping.phys,
            virt: mapping.virt,
            next,
        })
    }

    fn apply_layout(&self, phys: AddrRange<PhysAddr>, virt: AddrRange<VirtAddr>) {
        assert!(
            virt.end.as_usize() > virt.start.as_usize(),
            "heap range must be non-empty"
        );

        {
            let mut mapping = self.mapping.lock();
            if mapping.is_some() {
                panic!("kernel heap already initialized");
            }
            *mapping = Some(HeapMapping { phys, virt });
        }

        let mut guard = self.allocator.lock();
        unsafe {
            guard.init(virt);
        }
    }
}

unsafe impl GlobalAlloc for KernelHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut guard = self.allocator.lock();
        guard
            .allocate(layout)
            .map(NonNull::as_ptr)
            .unwrap_or(ptr::null_mut())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut guard = self.allocator.lock();
        unsafe {
            guard.dealloc(ptr, layout);
        }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: KernelHeap = KernelHeap::new();

#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    panic!("allocation failed: {:?}", layout);
}
