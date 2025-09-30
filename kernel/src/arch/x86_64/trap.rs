use x86_64::{VirtAddr, structures::idt::InterruptDescriptorTable};

use crate::trap::{TrapFrame as TrapFrameTrait, TrapInfo, TrapOrigin};
use crate::util::lazylock::LazyLock;

const GENERAL_REGS_SIZE: usize = core::mem::size_of::<GeneralRegisters>();
const ORIGINAL_ERROR_OFFSET: usize = 8 + GENERAL_REGS_SIZE;

#[repr(C)]
#[derive(Debug)]
pub struct GeneralRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct TrapFrame {
    pub error_code: u64,
    pub regs: GeneralRegisters,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl TrapFrameTrait for TrapFrame {
    fn error_code(&self) -> Option<u64> {
        Some(self.error_code)
    }
}

static IDT: LazyLock<InterruptDescriptorTable, fn() -> InterruptDescriptorTable> =
    LazyLock::new_const(build_idt);

macro_rules! define_trap_stub_no_error {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() -> ! {
            core::arch::naked_asm!(
                r#"
                    push r15
                    push r14
                    push r13
                    push r12
                    push r11
                    push r10
                    push r9
                    push r8
                    push rbp
                    push rdi
                    push rsi
                    push rdx
                    push rcx
                    push rbx
                    push rax
                    push 0
                    mov rsi, rsp
                    sub rsp, 8
                    mov edi, {vector}
                    xor edx, edx
                    call {dispatch}
                    add rsp, 8
                    add rsp, 8
                    pop rax
                    pop rbx
                    pop rcx
                    pop rdx
                    pop rsi
                    pop rdi
                    pop rbp
                    pop r8
                    pop r9
                    pop r10
                    pop r11
                    pop r12
                    pop r13
                    pop r14
                    pop r15
                    iretq
                "#,
                vector = const $vector,
                dispatch = sym dispatch_trap
            );
        }
    };
}

macro_rules! define_trap_stub_with_error {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() -> ! {
            core::arch::naked_asm!(
                r#"
                    push r15
                    push r14
                    push r13
                    push r12
                    push r11
                    push r10
                    push r9
                    push r8
                    push rbp
                    push rdi
                    push rsi
                    push rdx
                    push rcx
                    push rbx
                    push rax
                    push 0
                    mov rsi, rsp
                    mov rdx, [rsi + {orig_error_offset}]
                    mov [rsi], rdx
                    sub rsp, 8
                    mov edi, {vector}
                    mov edx, 1
                    call {dispatch}
                    add rsp, 8
                    add rsp, 8
                    pop rax
                    pop rbx
                    pop rcx
                    pop rdx
                    pop rsi
                    pop rdi
                    pop rbp
                    pop r8
                    pop r9
                    pop r10
                    pop r11
                    pop r12
                    pop r13
                    pop r14
                    pop r15
                    add rsp, 8
                    iretq
                "#,
                vector = const $vector,
                dispatch = sym dispatch_trap,
                orig_error_offset = const ORIGINAL_ERROR_OFFSET
            );
        }
    };
}

define_trap_stub_no_error!(exception_0, 0);
define_trap_stub_no_error!(exception_1, 1);
define_trap_stub_no_error!(exception_2, 2);
define_trap_stub_no_error!(exception_3, 3);
define_trap_stub_no_error!(exception_4, 4);
define_trap_stub_no_error!(exception_5, 5);
define_trap_stub_no_error!(exception_6, 6);
define_trap_stub_no_error!(exception_7, 7);
define_trap_stub_with_error!(exception_8, 8);
define_trap_stub_with_error!(exception_10, 10);
define_trap_stub_with_error!(exception_11, 11);
define_trap_stub_with_error!(exception_12, 12);
define_trap_stub_with_error!(exception_13, 13);
define_trap_stub_with_error!(exception_14, 14);
define_trap_stub_no_error!(exception_16, 16);
define_trap_stub_with_error!(exception_17, 17);
define_trap_stub_no_error!(exception_18, 18);
define_trap_stub_no_error!(exception_19, 19);
define_trap_stub_no_error!(exception_20, 20);
define_trap_stub_with_error!(exception_21, 21);
define_trap_stub_no_error!(exception_28, 28);
define_trap_stub_no_error!(exception_29, 29);
define_trap_stub_with_error!(exception_30, 30);

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

pub(super) fn init() {
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
            .set_handler_addr(VirtAddr::new(exception_2 as u64));
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
            .set_handler_addr(VirtAddr::new(exception_8 as u64));
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
            .set_handler_addr(VirtAddr::new(exception_18 as u64));
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
    }
    idt
}

#[unsafe(no_mangle)]
unsafe extern "C" fn dispatch_trap(vector: u8, has_error: u8, frame: *mut TrapFrame) {
    let frame = unsafe { &mut *frame }; // raw pointer originates from assembly stub
    let description = description_for(vector);
    let origin = origin_for(vector);
    let info = TrapInfo {
        vector,
        origin,
        description,
        has_error_code: has_error != 0,
    };
    crate::trap::dispatch(info, frame);
}

fn description_for(vector: u8) -> &'static str {
    EXCEPTION_DESCRIPTIONS
        .get(vector as usize)
        .copied()
        .unwrap_or("External Interrupt")
}

fn origin_for(vector: u8) -> TrapOrigin {
    match vector {
        2 => TrapOrigin::NonMaskable,
        v if v < 32 => TrapOrigin::Exception,
        v if v >= 32 && v < 240 => TrapOrigin::Interrupt,
        _ => TrapOrigin::Unknown,
    }
}
