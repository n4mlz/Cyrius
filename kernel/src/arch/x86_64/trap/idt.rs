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
            .set_handler_addr(VirtAddr::new(exception_0 as u64));
        idt.debug
            .set_handler_addr(VirtAddr::new(exception_1 as u64));
        idt.non_maskable_interrupt
            .set_handler_addr(VirtAddr::new(exception_2 as u64))
            .set_stack_index(IST_INDEX_NMI);
        idt.breakpoint
            .set_handler_addr(VirtAddr::new(exception_3 as u64));
        idt.overflow
            .set_handler_addr(VirtAddr::new(exception_4 as u64));
        idt.bound_range_exceeded
            .set_handler_addr(VirtAddr::new(exception_5 as u64));
        idt.invalid_opcode
            .set_handler_addr(VirtAddr::new(exception_6 as u64));
        idt.device_not_available
            .set_handler_addr(VirtAddr::new(exception_7 as u64));
        idt.double_fault
            .set_handler_addr(VirtAddr::new(exception_8 as u64))
            .set_stack_index(IST_INDEX_DOUBLE_FAULT);
        idt.invalid_tss
            .set_handler_addr(VirtAddr::new(exception_10 as u64));
        idt.segment_not_present
            .set_handler_addr(VirtAddr::new(exception_11 as u64));
        idt.stack_segment_fault
            .set_handler_addr(VirtAddr::new(exception_12 as u64));
        idt.general_protection_fault
            .set_handler_addr(VirtAddr::new(exception_13 as u64));
        idt.page_fault
            .set_handler_addr(VirtAddr::new(exception_14 as u64));
        idt.x87_floating_point
            .set_handler_addr(VirtAddr::new(exception_16 as u64));
        idt.alignment_check
            .set_handler_addr(VirtAddr::new(exception_17 as u64));
        idt.machine_check
            .set_handler_addr(VirtAddr::new(exception_18 as u64))
            .set_stack_index(IST_INDEX_MACHINE_CHECK);
        idt.simd_floating_point
            .set_handler_addr(VirtAddr::new(exception_19 as u64));
        idt.virtualization
            .set_handler_addr(VirtAddr::new(exception_20 as u64));
        idt.cp_protection_exception
            .set_handler_addr(VirtAddr::new(exception_21 as u64));
        idt.hv_injection_exception
            .set_handler_addr(VirtAddr::new(exception_28 as u64));
        idt.vmm_communication_exception
            .set_handler_addr(VirtAddr::new(exception_29 as u64));
        idt.security_exception
            .set_handler_addr(VirtAddr::new(exception_30 as u64));
        idt[super::super::interrupt::TIMER_VECTOR]
            .set_handler_addr(VirtAddr::new(interrupt_timer as u64));
    }
    idt
}
