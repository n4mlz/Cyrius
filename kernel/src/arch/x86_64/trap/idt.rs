use x86_64::{VirtAddr, structures::idt::InterruptDescriptorTable};

use crate::util::lazylock::LazyLock;

use super::gdt::{IST_INDEX_DOUBLE_FAULT, IST_INDEX_MACHINE_CHECK, IST_INDEX_NMI};
use super::stubs::{
    exception_0, exception_1, exception_2, exception_3, exception_4, exception_5, exception_6,
    exception_7, exception_8, exception_10, exception_11, exception_12, exception_13, exception_14,
    exception_16, exception_17, exception_18, exception_19, exception_20, exception_21,
    exception_28, exception_29, exception_30, interrupt_timer,
};

static IDT: LazyLock<InterruptDescriptorTable, fn() -> InterruptDescriptorTable> =
    LazyLock::new_const(build_idt);

pub(super) fn load() {
    let idt: &InterruptDescriptorTable = &IDT;
    idt.load();
}

fn build_idt() -> InterruptDescriptorTable {
    let mut idt = InterruptDescriptorTable::new();
    unsafe {
        idt.divide_error
            .set_handler_addr(VirtAddr::from_ptr(exception_0 as *const ()));
        idt.debug
            .set_handler_addr(VirtAddr::from_ptr(exception_1 as *const ()));
        idt.non_maskable_interrupt
            .set_handler_addr(VirtAddr::from_ptr(exception_2 as *const ()))
            .set_stack_index(IST_INDEX_NMI);
        idt.breakpoint
            .set_handler_addr(VirtAddr::from_ptr(exception_3 as *const ()));
        idt.overflow
            .set_handler_addr(VirtAddr::from_ptr(exception_4 as *const ()));
        idt.bound_range_exceeded
            .set_handler_addr(VirtAddr::from_ptr(exception_5 as *const ()));
        idt.invalid_opcode
            .set_handler_addr(VirtAddr::from_ptr(exception_6 as *const ()));
        idt.device_not_available
            .set_handler_addr(VirtAddr::from_ptr(exception_7 as *const ()));
        idt.double_fault
            .set_handler_addr(VirtAddr::from_ptr(exception_8 as *const ()))
            .set_stack_index(IST_INDEX_DOUBLE_FAULT);
        idt.invalid_tss
            .set_handler_addr(VirtAddr::from_ptr(exception_10 as *const ()));
        idt.segment_not_present
            .set_handler_addr(VirtAddr::from_ptr(exception_11 as *const ()));
        idt.stack_segment_fault
            .set_handler_addr(VirtAddr::from_ptr(exception_12 as *const ()));
        idt.general_protection_fault
            .set_handler_addr(VirtAddr::from_ptr(exception_13 as *const ()));
        idt.page_fault
            .set_handler_addr(VirtAddr::from_ptr(exception_14 as *const ()));
        idt.x87_floating_point
            .set_handler_addr(VirtAddr::from_ptr(exception_16 as *const ()));
        idt.alignment_check
            .set_handler_addr(VirtAddr::from_ptr(exception_17 as *const ()));
        idt.machine_check
            .set_handler_addr(VirtAddr::from_ptr(exception_18 as *const ()))
            .set_stack_index(IST_INDEX_MACHINE_CHECK);
        idt.simd_floating_point
            .set_handler_addr(VirtAddr::from_ptr(exception_19 as *const ()));
        idt.virtualization
            .set_handler_addr(VirtAddr::from_ptr(exception_20 as *const ()));
        idt.cp_protection_exception
            .set_handler_addr(VirtAddr::from_ptr(exception_21 as *const ()));
        idt.hv_injection_exception
            .set_handler_addr(VirtAddr::from_ptr(exception_28 as *const ()));
        idt.vmm_communication_exception
            .set_handler_addr(VirtAddr::from_ptr(exception_29 as *const ()));
        idt.security_exception
            .set_handler_addr(VirtAddr::from_ptr(exception_30 as *const ()));
        idt[super::super::interrupt::TIMER_VECTOR]
            .set_handler_addr(VirtAddr::from_ptr(interrupt_timer as *const ()));
    }
    idt
}
