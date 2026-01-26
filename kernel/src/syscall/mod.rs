mod host;
mod linux;

use core::sync::atomic::{AtomicU8, Ordering};

pub use host::HostSyscall;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Abi {
    Host,
    Linux,
}

impl Abi {
    fn from_raw(raw: u8) -> Self {
        match raw {
            1 => Self::Linux,
            _ => Self::Host,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SysError {
    NotImplemented,
    InvalidArgument,
    NotFound,
    BadAddress,
    NotTty,
}

pub type SysResult = Result<u64, SysError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchResult {
    Completed(SysResult),
    Terminate(i32),
}

/// Global ABI selection used by the syscall dispatcher. Stored as a raw `u8` so handlers can
/// update/load without locks; the enum discriminants provide the encoding.
/// The scheduler updates this on every context switch so the interrupt handler does not need to
/// reach into scheduler state.
static CURRENT_ABI: AtomicU8 = AtomicU8::new(Abi::Host as u8);

pub fn set_current_abi(abi: Abi) {
    CURRENT_ABI.store(abi as u8, Ordering::Release);
}

pub fn current_abi() -> Abi {
    Abi::from_raw(CURRENT_ABI.load(Ordering::Acquire))
}

/// Dispatch a syscall for the given ABI.
pub fn dispatch(abi: Abi, invocation: &SyscallInvocation) -> DispatchResult {
    dispatch_with_frame(abi, invocation, None)
}

pub fn dispatch_with_frame(
    abi: Abi,
    invocation: &SyscallInvocation,
    frame: Option<&mut crate::trap::CurrentTrapFrame>,
) -> DispatchResult {
    match abi {
        Abi::Host => DispatchResult::Completed(host::dispatch(invocation)),
        Abi::Linux => linux::dispatch(invocation, frame),
    }
}

/// Encode a syscall result into an ABI-specific return value.
pub fn encode_result(abi: Abi, result: SysResult) -> u64 {
    match abi {
        Abi::Host => host::encode_result(result),
        Abi::Linux => linux::encode_result(result),
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SyscallInvocation {
    pub number: u64,
    args: [u64; 6],
}

impl SyscallInvocation {
    pub fn new(number: u64, args: [u64; 6]) -> Self {
        Self { number, args }
    }

    pub fn arg(&self, index: usize) -> Option<u64> {
        self.args.get(index).copied()
    }
}

#[cfg(test)]
mod tests {
    use crate::{println, test::kernel_test_case};

    use super::*;

    #[kernel_test_case]
    fn error_translation_depends_on_abi() {
        println!("[test] error_translation_depends_on_abi");

        let invocation = SyscallInvocation::new(0xFFFF, [0; 6]);

        set_current_abi(Abi::Host);
        let host_val = match dispatch(current_abi(), &invocation) {
            DispatchResult::Completed(res) => encode_result(current_abi(), res),
            DispatchResult::Terminate(_) => panic!("host dispatch should not terminate"),
        };
        assert_eq!(host_val, host::encode_result(Err(SysError::NotImplemented)));

        set_current_abi(Abi::Linux);
        let linux_val = match dispatch(current_abi(), &invocation) {
            DispatchResult::Completed(res) => encode_result(current_abi(), res),
            DispatchResult::Terminate(_) => {
                panic!("linux dispatch should not terminate for ENOSYS")
            }
        };
        assert_eq!(
            linux_val,
            linux::encode_result(Err(SysError::NotImplemented))
        );
    }
}
