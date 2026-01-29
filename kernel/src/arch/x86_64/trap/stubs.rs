use super::build_trap_info;
use super::context::{ORIGINAL_ERROR_OFFSET, TrapFrame};
use crate::arch::{Arch, api::ArchTrap};

// Trap entry stubs assume:
// - Direction flag is cleared on entry (`cld`) before any Rust code runs.
// - The kernel is built with red-zone disabled (SysV ABI requires `-mno-red-zone`).
// - SIMD/FPU registers are not touched in the kernel until proper save/restore exists.

macro_rules! define_trap_stub_no_error {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        pub(super) unsafe extern "C" fn $name() -> ! {
            core::arch::naked_asm!(
                r#"
                    cld
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
                    mov r12, rsp
                    and r12, 0xF
                    jz 1f
                    sub rsp, 8
                    mov r12, 8
                    jmp 2f
                1:
                    xor r12, r12
                2:
                    mov edi, {vector}
                    xor edx, edx

                    call {dispatch}

                    add rsp, r12
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
        pub(super) unsafe extern "C" fn $name() -> ! {
            core::arch::naked_asm!(
                r#"
                    cld
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
                    mov rax, [rsi + {orig_error_offset}]
                    mov [rsi], rax
                    lea rdi, [rsi + {orig_error_offset}]
                    mov rbx, [rdi + 16]
                    test bx, 3
                    jz 1f
                    mov rax, [rdi + 8]
                    mov rcx, [rdi + 16]
                    mov rdx, [rdi + 24]
                    mov r8, [rdi + 32]
                    mov r9, [rdi + 40]
                    mov [rdi], rax
                    mov [rdi + 8], rcx
                    mov [rdi + 16], rdx
                    mov [rdi + 24], r8
                    mov [rdi + 32], r9
                    jmp 2f
                1:
                    mov rax, [rdi + 8]
                    mov rcx, [rdi + 16]
                    mov rdx, [rdi + 24]
                    mov [rdi], rax
                    mov [rdi + 8], rcx
                    mov [rdi + 16], rdx
                2:

                    mov r12, rsp
                    and r12, 0xF
                    jz 3f
                    sub rsp, 8
                    mov r12, 8
                    jmp 4f
                3:
                    xor r12, r12
                4:
                    mov edi, {vector}
                    mov edx, 1

                    call {dispatch}

                    add rsp, r12
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
                dispatch = sym dispatch_trap,
                orig_error_offset = const ORIGINAL_ERROR_OFFSET
            );
        }
    };
}

// NOTE: Exception vectors with error codes are fixed by the CPU specification.
// A mismatch here will corrupt the stack frame and usually triple-fault on `iretq`.
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
define_trap_stub_no_error!(interrupt_timer, super::super::interrupt::TIMER_VECTOR);
define_trap_stub_no_error!(software_interrupt_syscall, super::SYSCALL_VECTOR);

define_trap_stub_no_error!(interrupt_external_0, crate::interrupt::DEVICE_VECTOR_BASE);
define_trap_stub_no_error!(
    interrupt_external_1,
    crate::interrupt::DEVICE_VECTOR_BASE + 1
);
define_trap_stub_no_error!(
    interrupt_external_2,
    crate::interrupt::DEVICE_VECTOR_BASE + 2
);
define_trap_stub_no_error!(
    interrupt_external_3,
    crate::interrupt::DEVICE_VECTOR_BASE + 3
);
define_trap_stub_no_error!(
    interrupt_external_4,
    crate::interrupt::DEVICE_VECTOR_BASE + 4
);
define_trap_stub_no_error!(
    interrupt_external_5,
    crate::interrupt::DEVICE_VECTOR_BASE + 5
);
define_trap_stub_no_error!(
    interrupt_external_6,
    crate::interrupt::DEVICE_VECTOR_BASE + 6
);
define_trap_stub_no_error!(
    interrupt_external_7,
    crate::interrupt::DEVICE_VECTOR_BASE + 7
);
define_trap_stub_no_error!(
    interrupt_external_8,
    crate::interrupt::DEVICE_VECTOR_BASE + 8
);
define_trap_stub_no_error!(
    interrupt_external_9,
    crate::interrupt::DEVICE_VECTOR_BASE + 9
);
define_trap_stub_no_error!(
    interrupt_external_10,
    crate::interrupt::DEVICE_VECTOR_BASE + 10
);
define_trap_stub_no_error!(
    interrupt_external_11,
    crate::interrupt::DEVICE_VECTOR_BASE + 11
);
define_trap_stub_no_error!(
    interrupt_external_12,
    crate::interrupt::DEVICE_VECTOR_BASE + 12
);
define_trap_stub_no_error!(
    interrupt_external_13,
    crate::interrupt::DEVICE_VECTOR_BASE + 13
);
define_trap_stub_no_error!(
    interrupt_external_14,
    crate::interrupt::DEVICE_VECTOR_BASE + 14
);
define_trap_stub_no_error!(
    interrupt_external_15,
    crate::interrupt::DEVICE_VECTOR_BASE + 15
);

pub(super) const EXTERNAL_INTERRUPT_STUBS: [unsafe extern "C" fn() -> !;
    crate::interrupt::DEVICE_VECTOR_COUNT] = [
    interrupt_external_0,
    interrupt_external_1,
    interrupt_external_2,
    interrupt_external_3,
    interrupt_external_4,
    interrupt_external_5,
    interrupt_external_6,
    interrupt_external_7,
    interrupt_external_8,
    interrupt_external_9,
    interrupt_external_10,
    interrupt_external_11,
    interrupt_external_12,
    interrupt_external_13,
    interrupt_external_14,
    interrupt_external_15,
];

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn dispatch_trap(vector: u8, frame: *mut TrapFrame, has_error: u8) {
    let frame = unsafe { &mut *frame };
    let info = build_trap_info(vector, has_error != 0);
    <Arch as ArchTrap>::dispatch_trap(info, frame);
}
