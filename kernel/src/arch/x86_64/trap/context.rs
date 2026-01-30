use crate::trap::TrapFrame as TrapFrameTrait;

pub(super) const GENERAL_REGS_SIZE: usize = core::mem::size_of::<GeneralRegisters>();
/// Byte offset from the trap frame base to the CPU-pushed error code slot.
pub(super) const ORIGINAL_ERROR_OFFSET: usize = 8 + GENERAL_REGS_SIZE;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
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

impl GeneralRegisters {
    pub const fn zero() -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
        }
    }
}

impl Default for GeneralRegisters {
    fn default() -> Self {
        Self::zero()
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TrapFrame {
    pub error_code: u64,
    pub regs: GeneralRegisters,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl TrapFrame {
    /// Returns the stack pointer if this trap involved a privilege level change.
    pub fn stack_pointer(&self) -> Option<u64> {
        let cpl = (self.cs & 3) as u8;
        if cpl != 0 { Some(self.rsp) } else { None }
    }

    /// Returns the stack segment if this trap involved a privilege level change.
    pub fn stack_segment(&self) -> Option<u64> {
        let cpl = (self.cs & 3) as u8;
        if cpl != 0 { Some(self.ss) } else { None }
    }
}

impl TrapFrameTrait for TrapFrame {
    fn error_code(&self) -> Option<u64> {
        // The stubs push a placeholder even for no-error exceptions, so `0` means "no error".
        Some(self.error_code)
    }
}
