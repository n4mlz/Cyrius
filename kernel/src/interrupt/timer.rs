use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::{
    Arch,
    api::{ArchInterrupt, TimerDriver, TimerError, TimerMode, TimerTicks},
};
use crate::trap::{CurrentTrapFrame, TrapInfo};
use crate::{print, println};

use super::{InterruptError, InterruptServiceRoutine, ensure_initialised, register_handler};

struct DefaultTimerHandler {
    ticks: AtomicU64,
}

impl DefaultTimerHandler {
    const fn new() -> Self {
        Self {
            ticks: AtomicU64::new(0),
        }
    }
}

impl InterruptServiceRoutine for DefaultTimerHandler {
    fn handle(&self, _info: TrapInfo, _frame: &mut CurrentTrapFrame) {
        let count = self.ticks.fetch_add(1, Ordering::Relaxed);
        if count == 0 {
            println!("[timer] first tick");
        }
    }
}

static DEFAULT_TIMER_HANDLER: DefaultTimerHandler = DefaultTimerHandler::new();
static DEFAULT_HANDLER_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Return the number of timer interrupts observed by the default handler.
///
/// # Note
///
/// This counter only increases when [`init_system_timer`] registers the default handler for the
/// architecture timer. Calling this before initialisation, or after replacing the handler, will
/// always return zero.
pub fn observed_ticks() -> u64 {
    DEFAULT_TIMER_HANDLER.ticks.load(Ordering::Relaxed)
}

/// Configure the system timer in periodic mode using architecture-specific tick units.
pub fn init_system_timer(ticks: TimerTicks) -> Result<(), TimerError> {
    ensure_initialised()?;

    if ticks.raw() == 0 {
        return Err(TimerError::InvalidTicks);
    }

    ensure_default_handler()?;

    <Arch as ArchInterrupt>::timer().configure(TimerMode::Periodic, ticks)
}

pub fn stop_system_timer() -> Result<(), TimerError> {
    ensure_initialised()?;
    <Arch as ArchInterrupt>::timer().stop()
}

fn ensure_default_handler() -> Result<(), TimerError> {
    if DEFAULT_HANDLER_REGISTERED.load(Ordering::Acquire) {
        return Ok(());
    }

    if DEFAULT_HANDLER_REGISTERED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Ok(());
    }

    let vector = <Arch as ArchInterrupt>::timer_vector();
    match register_handler(vector, &DEFAULT_TIMER_HANDLER) {
        Ok(()) | Err(InterruptError::HandlerAlreadyRegistered) => Ok(()),
        Err(InterruptError::InvalidVector) => {
            DEFAULT_HANDLER_REGISTERED.store(false, Ordering::Release);
            Err(TimerError::HardwareError)
        }
        Err(InterruptError::NotInitialised) => {
            DEFAULT_HANDLER_REGISTERED.store(false, Ordering::Release);
            Err(TimerError::NotInitialised)
        }
    }
}
