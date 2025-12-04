use crate::interrupt::{INTERRUPTS, InterruptError, InterruptServiceRoutine};
use crate::syscall::{self, SyscallInvocation};
use crate::trap::{CurrentTrapFrame, TrapInfo};

use super::SYSCALL_VECTOR;

struct SyscallHandler;

static SYSCALL_HANDLER: SyscallHandler = SyscallHandler;

pub fn init() -> Result<(), InterruptError> {
    INTERRUPTS.register_handler(SYSCALL_VECTOR, &SYSCALL_HANDLER)
}

impl InterruptServiceRoutine for SyscallHandler {
    fn handle(&self, _info: TrapInfo, frame: &mut CurrentTrapFrame) {
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
        let result = syscall::dispatch(abi, &invocation);
        frame.regs.rax = syscall::encode_result(abi, result);
    }
}
