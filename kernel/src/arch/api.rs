use bootloader_api::BootInfo;

use crate::mem::addr::{AddrRange, VirtAddr};

pub trait ArchPlatform {
    fn name() -> &'static str;
}

pub trait ArchDevice {
    fn console() -> &'static dyn crate::device::char::uart::Uart<Error = ()>;
}

pub trait ArchTrap {
    type Frame: crate::trap::TrapFrame;

    fn init_traps();
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptInitError {
    MissingPhysicalMapping,
    AddressOverflow,
    ApicUnavailable,
    AlreadyInitialised,
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
}
