use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::registers::{
    model_specific::{Efer, EferFlags, Msr},
    rflags::RFlags,
};

use crate::mem::addr::VirtAddr;

use super::gdt;
use super::trap::SYSCALL_VECTOR;

const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;

static SYSCALL_STACK_TOP: AtomicU64 = AtomicU64::new(0);
static USER_CS_SELECTOR: AtomicU64 = AtomicU64::new(0);
static USER_SS_SELECTOR: AtomicU64 = AtomicU64::new(0);
static SAVED_USER_RSP: AtomicU64 = AtomicU64::new(0);

pub(super) fn init() {
    let selectors = gdt::selectors();

    USER_CS_SELECTOR.store(selectors.user_code.0 as u64, Ordering::Relaxed);
    USER_SS_SELECTOR.store(selectors.user_data.0 as u64, Ordering::Relaxed);

    let kernel_cs = selectors.kernel_code.0 as u64;
    let user_cs = selectors.user_code.0 as u64;

    unsafe {
        let mut efer = Efer::read();
        if !efer.contains(EferFlags::SYSTEM_CALL_EXTENSIONS) {
            efer.insert(EferFlags::SYSTEM_CALL_EXTENSIONS);
            Efer::write(efer);
        }

        let star = (user_cs << 48) | (kernel_cs << 32);
        Msr::new(IA32_STAR).write(star);
        Msr::new(IA32_LSTAR).write(syscall_entry as u64);
        Msr::new(IA32_FMASK).write(RFlags::INTERRUPT_FLAG.bits());
    }
}

pub(super) fn update_kernel_stack(stack_top: VirtAddr) {
    SYSCALL_STACK_TOP.store(stack_top.as_raw() as u64, Ordering::Release);
}

#[unsafe(naked)]
pub(super) unsafe extern "C" fn syscall_entry() -> ! {
    core::arch::naked_asm!(
        r#"
            mov qword ptr [rip + {saved_rsp}], rsp
            mov rsp, qword ptr [rip + {stack_top}]

            push qword ptr [rip + {user_ss}]
            push qword ptr [rip + {saved_rsp}]
            push r11
            push qword ptr [rip + {user_cs}]
            push rcx

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
        dispatch = sym super::trap::dispatch_trap,
        vector = const SYSCALL_VECTOR,
        stack_top = sym SYSCALL_STACK_TOP,
        user_cs = sym USER_CS_SELECTOR,
        user_ss = sym USER_SS_SELECTOR,
        saved_rsp = sym SAVED_USER_RSP
    );
}
