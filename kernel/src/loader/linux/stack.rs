use core::mem::size_of;

use crate::mem::addr::{VirtAddr, align_down};

pub fn initialise_minimal_stack(stack_top: VirtAddr) -> VirtAddr {
    let mut sp = align_down(stack_top.as_raw(), 16);

    // auxv terminator
    sp -= size_of::<u64>();
    unsafe { *(sp as *mut u64) = 0 };
    sp -= size_of::<u64>();
    unsafe { *(sp as *mut u64) = 0 };

    // envp null
    sp -= size_of::<u64>();
    unsafe { *(sp as *mut u64) = 0 };

    // argv null
    sp -= size_of::<u64>();
    unsafe { *(sp as *mut u64) = 0 };

    // argc = 0
    sp -= size_of::<u64>();
    unsafe { *(sp as *mut u64) = 0 };

    VirtAddr::new(sp)
}
