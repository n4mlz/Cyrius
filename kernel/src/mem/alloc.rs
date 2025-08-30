use core::{
    alloc::{GlobalAlloc, Layout},
    cell::RefCell,
    ptr,
};

pub struct Allocator {
    head: RefCell<*mut u8>,
    end: *const u8,
}

impl Allocator {
    const fn new(start: *mut u8, end: *const u8) -> Self {
        Allocator {
            head: RefCell::new(start),
            end,
        }
    }
}

unsafe impl Sync for Allocator {}

unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let head = *self.head.borrow();

        let size = layout.size();
        let align = layout.align();

        let padding = head.align_offset(align);
        let alloc_start = unsafe { head.add(padding) };
        let alloc_end = unsafe { alloc_start.add(size) };

        if alloc_end as *const u8 > self.end {
            ptr::null_mut()
        } else {
            unsafe { ptr::write_bytes(alloc_start, 0, size) };

            let mut head = self.head.borrow_mut();
            *head = alloc_end;

            alloc_start
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}
