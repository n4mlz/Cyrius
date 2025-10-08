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
pub use timer::{init_system_timer, stop_system_timer};

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

static INITIALISED: AtomicBool = AtomicBool::new(false);
static HANDLERS: SpinLock<[Option<&'static dyn InterruptServiceRoutine>; VECTOR_COUNT]> =
    SpinLock::new([None; VECTOR_COUNT]);

struct InterruptDispatcher;

static DISPATCHER: InterruptDispatcher = InterruptDispatcher;

pub fn init(boot_info: &'static BootInfo) -> Result<(), InterruptInitError> {
    if INITIALISED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Err(InterruptInitError::AlreadyInitialised);
    }

    trap::init();

    if let Err(err) = <Arch as ArchInterrupt>::init_interrupts(boot_info) {
        INITIALISED.store(false, Ordering::Release);
        return Err(err);
    }

    trap::register_handler(&DISPATCHER);

    Ok(())
}

pub fn register_handler(
    vector: u8,
    handler: &'static dyn InterruptServiceRoutine,
) -> Result<(), InterruptError> {
    if !is_initialised() {
        return Err(InterruptError::NotInitialised);
    }

    if vector < 32 || vector as usize >= VECTOR_COUNT {
        return Err(InterruptError::InvalidVector);
    }

    let mut table = HANDLERS.lock();
    let slot = &mut table[vector as usize];
    if slot.is_some() {
        return Err(InterruptError::HandlerAlreadyRegistered);
    }
    *slot = Some(handler);
    Ok(())
}

pub fn enable() {
    <Arch as ArchInterrupt>::enable_interrupts();
}

pub fn disable() {
    <Arch as ArchInterrupt>::disable_interrupts();
}

pub(super) fn ensure_initialised() -> Result<(), TimerError> {
    if is_initialised() {
        Ok(())
    } else {
        Err(TimerError::NotInitialised)
    }
}

fn is_initialised() -> bool {
    INITIALISED.load(Ordering::Acquire)
}

impl TrapHandler for InterruptDispatcher {
    fn handle_trap(&self, info: TrapInfo, frame: &mut CurrentTrapFrame) {
        match info.origin {
            TrapOrigin::Interrupt => {
                handle_interrupt(info, frame);
            }
            TrapOrigin::Exception | TrapOrigin::NonMaskable | TrapOrigin::Unknown => {
                log_trap(info, frame);
            }
        }
    }
}

fn handle_interrupt(info: TrapInfo, frame: &mut CurrentTrapFrame) {
    let handler = {
        let table = HANDLERS.lock();
        table.get(info.vector as usize).copied().unwrap_or(None)
    };

    if let Some(handler) = handler {
        handler.handle(info, frame);
    } else {
        log_unhandled_interrupt(info);
    }

    <Arch as ArchInterrupt>::end_of_interrupt(info.vector);
}

fn log_unhandled_interrupt(info: TrapInfo) {
    println!(
        "[interrupt] vector={} origin={:?} desc={} (no handler)",
        info.vector, info.origin, info.description
    );
}

fn log_trap(info: TrapInfo, frame: &mut CurrentTrapFrame) {
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
