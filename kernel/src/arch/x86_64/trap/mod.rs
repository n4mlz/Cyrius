mod context;
pub(crate) mod gdt;
mod handlers;
mod idt;
mod stubs;

pub use context::{GeneralRegisters, TrapFrame};

use crate::trap::{TrapInfo, TrapOrigin};

pub(super) fn init() {
    gdt::load();
    idt::load();
}

pub const SYSCALL_VECTOR: u8 = 0x80;

pub(super) fn handle_exception(info: TrapInfo, frame: &mut TrapFrame) -> bool {
    handlers::handle_exception(info, frame)
}

const EXCEPTION_DESCRIPTIONS: [&str; 32] = [
    "Divide Error",
    "Debug",
    "Non Maskable Interrupt",
    "Breakpoint",
    "Overflow",
    "Bound Range Exceeded",
    "Invalid Opcode",
    "Device Not Available",
    "Double Fault",
    "Coprocessor Segment Overrun",
    "Invalid TSS",
    "Segment Not Present",
    "Stack Segment Fault",
    "General Protection Fault",
    "Page Fault",
    "Reserved",
    "x87 Floating Point",
    "Alignment Check",
    "Machine Check",
    "SIMD Floating Point",
    "Virtualization",
    "Control Protection",
    "Hypervisor Injection",
    "VMM Communication",
    "Security",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
];

pub(super) fn description_for(vector: u8) -> &'static str {
    EXCEPTION_DESCRIPTIONS
        .get(vector as usize)
        .copied()
        .unwrap_or("External Interrupt")
}

pub(super) fn origin_for(vector: u8) -> TrapOrigin {
    match vector {
        2 => TrapOrigin::NonMaskable,
        v if v < 32 => TrapOrigin::Exception,
        v if (32..240).contains(&v) => TrapOrigin::Interrupt,
        _ => TrapOrigin::Unknown,
    }
}

pub(super) fn build_trap_info(vector: u8, has_error: bool) -> TrapInfo {
    TrapInfo {
        vector,
        origin: origin_for(vector),
        description: description_for(vector),
        has_error_code: has_error,
    }
}

#[cfg(test)]
pub(crate) fn arm_user_pf_frame_check(
    pid: crate::process::ProcessId,
    expected_fault_addr: u64,
) {
    handlers::arm_user_pf_frame_check(pid, expected_fault_addr);
}

#[cfg(test)]
pub(crate) fn user_pf_frame_check_passed() -> bool {
    handlers::user_pf_frame_check_passed()
}
