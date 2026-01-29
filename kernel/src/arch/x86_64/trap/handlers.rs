use x86_64::instructions::interrupts;
use x86_64::registers::control::Cr2;

use crate::arch::api::ArchPageTableAccess;
use crate::mem::paging::{PageTableOps, PhysMapper};
use crate::println;
use crate::process::PROCESS_TABLE;
use crate::syscall::{self, SyscallInvocation};
use crate::thread::SCHEDULER;
use crate::trap::TrapInfo;
use crate::{
    mem::{
        addr::{VirtAddr, VirtIntoPtr},
        manager,
    },
};

use super::TrapFrame;
#[cfg(test)]
use super::context::ORIGINAL_ERROR_OFFSET;
#[cfg(test)]
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};
#[cfg(test)]
use crate::process::ProcessId;

#[cfg(test)]
static USER_PF_FRAME_CHECK_STATE: AtomicU8 = AtomicU8::new(0);
#[cfg(test)]
static USER_PF_FRAME_CHECK_PID: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static USER_PF_FRAME_CHECK_ADDR: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
pub(crate) fn arm_user_pf_frame_check(pid: ProcessId, expected_fault_addr: u64) {
    USER_PF_FRAME_CHECK_PID.store(pid, Ordering::SeqCst);
    USER_PF_FRAME_CHECK_ADDR.store(expected_fault_addr, Ordering::SeqCst);
    USER_PF_FRAME_CHECK_STATE.store(1, Ordering::SeqCst);
}

#[cfg(test)]
pub(crate) fn user_pf_frame_check_passed() -> bool {
    USER_PF_FRAME_CHECK_STATE.load(Ordering::SeqCst) == 2
}

pub fn handle_exception(info: TrapInfo, frame: &mut TrapFrame) -> bool {
    // Be careful with logging/locking here: traps can occur while locks are held or
    // interrupts are disabled, and double faults must avoid re-entrancy entirely.
    match info.vector {
        14 => {
            handle_page_fault(frame)
        }
        6 => {
            handle_invalid_opcode(frame);
            true
        }
        13 => {
            handle_general_protection(frame);
            true
        }
        8 => handle_double_fault(frame),
        _ => false,
    }
}

fn handle_page_fault(frame: &mut TrapFrame) -> bool {
    let fault_addr = Cr2::read().expect("CR2 must contain a canonical address");
    let code = frame.error_code;
    let fs_base = x86_64::registers::model_specific::FsBase::read().as_u64();
    let cpl = (frame.cs & 3) as u8;

    let present = (code & 1) != 0;
    let write = (code & 1 << 1) != 0;
    let user = (code & 1 << 2) != 0 || (frame.cs & 3) != 0;
    let reserved = (code & 1 << 3) != 0;
    let instruction = (code & 1 << 4) != 0;

    #[cfg(test)]
    maybe_check_user_pf_frame(frame, fault_addr.as_u64());

    println!(
        "[#PF] fault_addr={:#x} present={} write={} user={} reserved={} instruction={} fs_base={:#x}",
        fault_addr.as_u64(),
        present,
        write,
        user,
        reserved,
        instruction,
        fs_base
    );
    println!(
        "[#PF] rip={:#x} cs={:#x} rsp={:#x} ss={:#x} cpl={}",
        frame.rip,
        frame.cs,
        frame.rsp,
        frame.ss,
        cpl
    );
    dump_trap_frame_qwords(frame);
    dump_frame_field_hints(frame);
    if fault_addr.as_u64() >= fs_base {
        println!(
            "[#PF] fault_addr-fs_base={:#x}",
            fault_addr.as_u64() - fs_base
        );
    }
    if let Some(pid) = SCHEDULER.current_process_id() {
        if let Ok(process) = PROCESS_TABLE.process_handle(pid) {
            let brk = process.brk_state();
            println!(
                "[#PF] pid={} brk_base={:#x} brk_current={:#x}",
                pid,
                brk.base.as_raw(),
                brk.current.as_raw()
            );
        }
    }
    if let Some(stack) = SCHEDULER.current_user_stack_info() {
        println!(
            "[#PF] user_stack base={:#x} size={:#x}",
            stack.base.as_raw(),
            stack.size
        );
    }
    dump_faulting_bytes(frame.rip as usize);
    println!("[#PF] frame={:#?}", frame);
    if user {
        if let Some(pid) = SCHEDULER.current_process_id() {
            if let Ok(process) = PROCESS_TABLE.process_handle(pid) {
                // Use a conventional non-zero status for user faults.
                process.set_exit_code(139);
            }
        }
        SCHEDULER.terminate_current(frame);
        return true;
    }
    panic!("page fault while executing in kernel context");
}

fn handle_general_protection(frame: &TrapFrame) {
    println!("[#GP] error_code={:#x}", frame.error_code);
    println!("[#GP] frame={:#?}", frame);
    panic!("general protection fault");
}

fn handle_invalid_opcode(frame: &mut TrapFrame) {
    if emulate_syscall_from_ud(frame) {
        return;
    }
    println!("[#UD] invalid opcode");
    println!("[#UD] frame={:#?}", frame);
    panic!("invalid opcode");
}

fn handle_double_fault(_frame: &TrapFrame) -> bool {
    // Double faults are fatal; avoid logging/locking to reduce the chance of
    // re-faulting and triggering a triple fault.
    interrupts::disable();
    loop {
        x86_64::instructions::hlt();
    }
}

fn dump_faulting_bytes(rip: usize) {
    let pid = match SCHEDULER.current_process_id() {
        Some(pid) => pid,
        None => return,
    };
    let process = match PROCESS_TABLE.process_handle(pid) {
        Ok(proc) => proc,
        Err(_) => return,
    };
    let mut bytes = [0u8; 16];
    let mut ok = true;
    process.address_space().with_page_table(|table, _| {
        for (idx, out) in bytes.iter_mut().enumerate() {
            let addr = match rip.checked_add(idx) {
                Some(addr) => addr,
                None => {
                    ok = false;
                    break;
                }
            };
            let virt = VirtAddr::new(addr);
            let phys = match table.translate(virt) {
                Ok(phys) => phys,
                Err(_) => {
                    ok = false;
                    break;
                }
            };
            let mapper = manager::phys_mapper();
            unsafe {
                let ptr = mapper.phys_to_virt(phys).into_ptr();
                *out = core::ptr::read(ptr);
            }
        }
    });
    if ok {
        println!(
            "[#PF] bytes @ rip: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7],
            bytes[8],
            bytes[9],
            bytes[10],
            bytes[11],
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15]
        );
    } else {
        println!("[#PF] bytes @ rip: <unmapped>");
    }
}

/// Emulate `syscall` on #UD in user mode as a compatibility workaround.
///
/// # Implicit dependencies
/// - Relies on the current process address space being active and readable.
/// - Assumes the syscall ABI register layout matches the Linux `syscall` calling convention
///   (rax, rdi, rsi, rdx, r10, r8, r9).
/// - Assumes #UD is raised because `SYSCALL/SYSRET` MSRs are not wired yet.
fn emulate_syscall_from_ud(frame: &mut TrapFrame) -> bool {
    let cpl = (frame.cs & 3) as u8;
    if cpl == 0 {
        return false;
    }
    let pid = match SCHEDULER.current_process_id() {
        Some(pid) => pid,
        None => return false,
    };
    let process = match PROCESS_TABLE.process_handle(pid) {
        Ok(proc) => proc,
        Err(_) => return false,
    };
    let rip = frame.rip as usize;
    let mut bytes = [0u8; 2];
    let mut ok = true;
    process.address_space().with_page_table(|table, _| {
        for (idx, out) in bytes.iter_mut().enumerate() {
            let addr = match rip.checked_add(idx) {
                Some(addr) => addr,
                None => {
                    ok = false;
                    break;
                }
            };
            let virt = VirtAddr::new(addr);
            let phys = match table.translate(virt) {
                Ok(phys) => phys,
                Err(_) => {
                    ok = false;
                    break;
                }
            };
            let mapper = manager::phys_mapper();
            unsafe {
                let ptr = mapper.phys_to_virt(phys).into_ptr();
                *out = core::ptr::read(ptr);
            }
        }
    });
    if !ok || bytes != [0x0f, 0x05] {
        return false;
    }

    let abi = syscall::current_abi();
    let invocation = SyscallInvocation::new(
        frame.regs.rax,
        [
            frame.regs.rdi,
            frame.regs.rsi,
            frame.regs.rdx,
            frame.regs.r10,
            frame.regs.r8,
            frame.regs.r9,
        ],
    );
    match syscall::dispatch_with_frame(abi, &invocation, Some(frame)) {
        syscall::DispatchResult::Completed(result) => {
            frame.regs.rax = syscall::encode_result(abi, result);
            frame.rip = frame.rip.wrapping_add(2);
        }
        syscall::DispatchResult::Terminate(_code) => {
            SCHEDULER.terminate_current(frame);
        }
    }
    true
}

fn dump_trap_frame_qwords(frame: &TrapFrame) {
    let base = frame as *const TrapFrame as *const u64;
    let mut slots = [0u64; 12];
    for (idx, slot) in slots.iter_mut().enumerate() {
        unsafe {
            *slot = core::ptr::read_volatile(base.add(idx));
        }
    }
    println!(
        "[#PF] frame qwords: {:016x} {:016x} {:016x} {:016x} {:016x} {:016x} {:016x} {:016x} {:016x} {:016x} {:016x} {:016x}",
        slots[0],
        slots[1],
        slots[2],
        slots[3],
        slots[4],
        slots[5],
        slots[6],
        slots[7],
        slots[8],
        slots[9],
        slots[10],
        slots[11]
    );
}

fn dump_frame_field_hints(frame: &TrapFrame) {
    let pid = SCHEDULER.current_process_id();
    let (brk_base, brk_current) = pid
        .and_then(|pid| PROCESS_TABLE.process_handle(pid).ok())
        .map(|proc| {
            let brk = proc.brk_state();
            (Some(brk.base.as_raw()), Some(brk.current.as_raw()))
        })
        .unwrap_or((None, None));
    let (stack_base, stack_size) = SCHEDULER
        .current_user_stack_info()
        .map(|stack| (Some(stack.base.as_raw()), Some(stack.size)))
        .unwrap_or((None, None));

    dump_field_hint("rip", frame.rip, brk_base, brk_current, stack_base, stack_size);
    dump_field_hint("cs", frame.cs, brk_base, brk_current, stack_base, stack_size);
    dump_field_hint("rflags", frame.rflags, brk_base, brk_current, stack_base, stack_size);
    dump_field_hint("rsp", frame.rsp, brk_base, brk_current, stack_base, stack_size);
    dump_field_hint("ss", frame.ss, brk_base, brk_current, stack_base, stack_size);
}

fn dump_field_hint(
    name: &str,
    value: u64,
    brk_base: Option<usize>,
    brk_current: Option<usize>,
    stack_base: Option<usize>,
    stack_size: Option<usize>,
) {
    let is_small = value <= 0xffff;
    let in_brk = match (brk_base, brk_current) {
        (Some(base), Some(current)) => {
            let addr = value as usize;
            addr >= base && addr < current
        }
        _ => false,
    };
    let in_stack = match (stack_base, stack_size) {
        (Some(base), Some(size)) => {
            let addr = value as usize;
            addr >= base && addr < base.saturating_add(size)
        }
        _ => false,
    };
    println!(
        "[#PF] {}={:#x} small={} in_brk={} in_stack={}",
        name,
        value,
        is_small,
        in_brk,
        in_stack
    );
}

#[cfg(test)]
fn maybe_check_user_pf_frame(frame: &TrapFrame, fault_addr: u64) {
    if USER_PF_FRAME_CHECK_STATE.load(Ordering::SeqCst) != 1 {
        return;
    }

    let expected_pid = USER_PF_FRAME_CHECK_PID.load(Ordering::SeqCst);
    let expected_addr = USER_PF_FRAME_CHECK_ADDR.load(Ordering::SeqCst);
    if SCHEDULER.current_process_id().unwrap_or(0) != expected_pid {
        return;
    }
    if fault_addr != expected_addr {
        return;
    }

    // Read the CPU-pushed exception frame starting at ORIGINAL_ERROR_OFFSET.
    let base = frame as *const TrapFrame as *const u8;
    let cpu_frame_ptr =
        unsafe { base.add(ORIGINAL_ERROR_OFFSET) as *const u64 };
    let mut cpu = [0u64; 5];
    for idx in 0..5 {
        unsafe {
            cpu[idx] = core::ptr::read_volatile(cpu_frame_ptr.add(idx));
        }
    }
    let cpl = (cpu[1] & 3) as u8;
    assert!(cpl != 0, "expected user-mode page fault");

    assert_eq!(frame.error_code, 4, "pf error_code unexpected");
    assert_eq!(cpu[0], frame.rip, "rip mismatch");
    assert_eq!(cpu[1], frame.cs, "cs mismatch");
    assert_eq!(cpu[2], frame.rflags, "rflags mismatch");
    assert_eq!(cpu[3], frame.rsp, "rsp mismatch");
    assert_eq!(cpu[4], frame.ss, "ss mismatch");

    USER_PF_FRAME_CHECK_STATE.store(2, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86_64::trap::context::GeneralRegisters;
    use crate::test::kernel_test_case;
    use crate::trap::TrapOrigin;

    #[kernel_test_case]
    fn other_vectors_fall_back() {
        println!("[test] other_vectors_fall_back");

        let info = TrapInfo {
            vector: 0x21,
            origin: TrapOrigin::Exception,
            description: "test",
            has_error_code: false,
        };
        let mut frame = TrapFrame {
            error_code: 0,
            regs: GeneralRegisters::zero(),
            rip: 0,
            cs: 0,
            rflags: 0,
            rsp: 0,
            ss: 0,
        };

        assert!(!handle_exception(info, &mut frame));
    }
}
