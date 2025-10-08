use core::sync::atomic::{AtomicBool, Ordering};

use bootloader_api::BootInfo;

use crate::arch::{
    Arch,
    api::{ArchInterrupt, InterruptInitError},
};
use crate::trap::{self, CurrentTrapFrame, TrapFrame, TrapHandler, TrapInfo, TrapOrigin};
use crate::util::spinlock::SpinLock;
use crate::{print, println};

pub mod timer;

pub use crate::arch::api::{TimerError, TimerMode, TimerTicks};
pub use timer::{SYSTEM_TIMER, SystemTimer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptError {
    InvalidVector,
    HandlerAlreadyRegistered,
    NotInitialised,
}

pub trait InterruptServiceRoutine: Sync {
    fn handle(&self, info: TrapInfo, frame: &mut CurrentTrapFrame);
}

const VECTOR_COUNT: usize = 256;

pub static INTERRUPTS: InterruptController = InterruptController::new();

pub struct InterruptController {
    initialised: AtomicBool,
    handlers: SpinLock<[Option<&'static dyn InterruptServiceRoutine>; VECTOR_COUNT]>,
}

impl InterruptController {
    pub const fn new() -> Self {
        Self {
            initialised: AtomicBool::new(false),
            handlers: SpinLock::new([None; VECTOR_COUNT]),
        }
    }

    pub fn init(&'static self, boot_info: &'static BootInfo) -> Result<(), InterruptInitError> {
        if self
            .initialised
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(InterruptInitError::AlreadyInitialised);
        }

        trap::init();

        if let Err(err) = <Arch as ArchInterrupt>::init_interrupts(boot_info) {
            self.initialised.store(false, Ordering::Release);
            return Err(err);
        }

        trap::register_handler(self);

        Ok(())
    }

    pub fn register_handler(
        &self,
        vector: u8,
        handler: &'static dyn InterruptServiceRoutine,
    ) -> Result<(), InterruptError> {
        if !self.is_initialised() {
            return Err(InterruptError::NotInitialised);
        }

        if vector < 32 || vector as usize >= VECTOR_COUNT {
            return Err(InterruptError::InvalidVector);
        }

        let mut table = self.handlers.lock();
        let slot = &mut table[vector as usize];
        if slot.is_some() {
            return Err(InterruptError::HandlerAlreadyRegistered);
        }
        *slot = Some(handler);
        Ok(())
    }

    pub fn enable(&self) {
        <Arch as ArchInterrupt>::enable_interrupts();
    }

    pub fn disable(&self) {
        <Arch as ArchInterrupt>::disable_interrupts();
    }

    pub(crate) fn ensure_initialised(&self) -> Result<(), TimerError> {
        if self.is_initialised() {
            Ok(())
        } else {
            Err(TimerError::NotInitialised)
        }
    }

    fn is_initialised(&self) -> bool {
        self.initialised.load(Ordering::Acquire)
    }

    fn handle_interrupt(&self, info: TrapInfo, frame: &mut CurrentTrapFrame) {
        let handler = {
            let table = self.handlers.lock();
            table.get(info.vector as usize).copied().unwrap_or(None)
        };

        if let Some(handler) = handler {
            handler.handle(info, frame);
        } else {
            self.log_unhandled_interrupt(info);
        }

        <Arch as ArchInterrupt>::end_of_interrupt(info.vector);
    }

    fn log_unhandled_interrupt(&self, info: TrapInfo) {
        println!(
            "[interrupt] vector={} origin={:?} desc={} (no handler)",
            info.vector, info.origin, info.description
        );
    }

    fn log_trap(&self, info: TrapInfo, frame: &mut CurrentTrapFrame) {
        println!(
            "[trap] vector={} origin={:?} desc={}",
            info.vector, info.origin, info.description
        );
        if info.has_error_code {
            match frame.error_code() {
                Some(code) => println!("[trap] error_code={:#x}", code),
                None => println!("[trap] error_code=<not exposed>"),
            }
        }
        println!("[trap] frame={:#?}", frame);
    }
}

impl TrapHandler for InterruptController {
    fn handle_trap(&self, info: TrapInfo, frame: &mut CurrentTrapFrame) {
        match info.origin {
            TrapOrigin::Interrupt => self.handle_interrupt(info, frame),
            TrapOrigin::Exception | TrapOrigin::NonMaskable | TrapOrigin::Unknown => {
                self.log_trap(info, frame);
            }
        }
    }
}
