use super::build_trap_info;
use super::context::{ORIGINAL_ERROR_OFFSET, TrapFrame};

macro_rules! define_trap_stub_no_error {
    ($name:ident, $vector:expr) => {
        #[unsafe(naked)]
        pub(super) unsafe extern "C" fn $name() -> ! {
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
define_trap_stub_no_error!(interrupt_timer, super::super::interrupt::TIMER_VECTOR);
define_trap_stub_no_error!(software_interrupt_syscall, super::SYSCALL_VECTOR);

#[unsafe(no_mangle)]
pub(super) unsafe extern "C" fn dispatch_trap(vector: u8, frame: *mut TrapFrame, has_error: u8) {
    let frame = unsafe { &mut *frame };
    let info = build_trap_info(vector, has_error != 0);
    crate::trap::dispatch(info, frame);
}
