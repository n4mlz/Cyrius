use bootloader_api::BootInfo;

use crate::mem::addr::{AddrRange, VirtAddr};
use crate::mem::paging::MapError;
use crate::trap::TrapInfo;

pub trait ArchPlatform {
    fn name() -> &'static str;
}

pub trait ArchDevice {
    type Console: crate::device::char::uart::Uart;

    fn console() -> &'static Self::Console;
}

pub trait ArchTrap {
    type Frame: crate::trap::TrapFrame;

    fn init_traps();

    /// Attempt to handle an exception; return `true` if fully handled.
    fn handle_exception(_info: TrapInfo, _frame: &mut Self::Frame) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapRegionError {
    MissingPhysicalMapping,
    NoUsableRegion,
    AddressOverflow,
}

pub trait ArchMemory {
    fn locate_kernel_heap(
        boot_info: &'static BootInfo,
    ) -> Result<AddrRange<VirtAddr>, HeapRegionError>;
}

/// Architecture-specific thread context management.
pub trait ArchThread {
    type Context: Clone;
    type AddressSpace: Clone;
    type UserStack;

    /// Capture the CPU context described by the current trap frame.
    fn save_context(frame: &crate::trap::CurrentTrapFrame) -> Self::Context;

    /// Restore CPU state into the provided trap frame so that the next `iret` resumes `ctx`.
    ///
    /// # Safety
    ///
    /// Callers must ensure that `frame` will be returned to the processor without additional
    /// modifications (other than the architecture-defined epilogue) and that the referenced
    /// context is valid and trusted.
    unsafe fn restore_context(frame: &mut crate::trap::CurrentTrapFrame, ctx: &Self::Context);

    /// Build an initial kernel-mode context for a fresh thread.
    ///
    /// # Implicit contract
    ///
    /// The caller must ensure that `stack_top` denotes the first unusable address beyond an owned
    /// stack region mapped with kernel read/write permissions.
    fn bootstrap_kernel_context(entry: VirtAddr, stack_top: VirtAddr) -> Self::Context;

    /// Build an initial user-mode context that resumes execution at `entry` on the supplied stack.
    fn bootstrap_user_context(entry: VirtAddr, user_stack_top: VirtAddr) -> Self::Context;

    /// Return a handle to the currently active address space.
    fn current_address_space() -> Self::AddressSpace;

    /// Activate a previously captured address space.
    ///
    /// # Safety
    ///
    /// Switching address spaces may invalidate existing virtual mappings. The caller must ensure
    /// that kernel text/data remain accessible and that interrupts are either disabled or handlers
    /// tolerate the transition.
    unsafe fn activate_address_space(space: &Self::AddressSpace);

    /// Allocate a user-mode stack within the provided address space.
    fn allocate_user_stack(
        space: &Self::AddressSpace,
        size: usize,
    ) -> Result<Self::UserStack, UserStackError>;

    /// Return the canonical top-of-stack for the provided user stack handle.
    fn user_stack_top(stack: &Self::UserStack) -> VirtAddr;

    /// Update the privilege-stack pointer used during user→kernel transitions.
    fn update_privilege_stack(stack_top: VirtAddr);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptInitError {
    MissingPhysicalMapping,
    AddressOverflow,
    ApicUnavailable,
    AlreadyInitialised,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserStackError {
    InvalidSize,
    AddressSpaceExhausted,
    OutOfMemory,
    MapFailed(MapError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerError {
    NotInitialised,
    AlreadyRunning,
    NotRunning,
    InvalidTicks,
    HardwareError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerMode {
    OneShot,
    Periodic,
}

/// Represents the architecture-specific tick count used to program the system timer.
///
/// The interpretation of the stored value depends on the underlying hardware implementation
/// and does not correspond to wall-clock time without additional calibration.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerTicks(u32);

impl TimerTicks {
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u32 {
        self.0
    }
}

pub trait TimerDriver: Sync {
    fn configure(&self, mode: TimerMode, ticks: TimerTicks) -> Result<(), TimerError>;
    fn stop(&self) -> Result<(), TimerError>;
}

pub trait ArchInterrupt {
    type Timer: TimerDriver;

    fn init_interrupts(boot_info: &'static BootInfo) -> Result<(), InterruptInitError>;

    fn enable_interrupts();
    fn disable_interrupts();
    fn end_of_interrupt(vector: u8);

    fn timer() -> &'static Self::Timer;
    fn timer_vector() -> u8;
    fn syscall_vector() -> u8;
}
