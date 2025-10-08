use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::{
    Arch,
    api::{ArchInterrupt, TimerDriver, TimerError, TimerMode, TimerTicks},
};
use crate::trap::{CurrentTrapFrame, TrapInfo};
use crate::{print, println};

use super::{INTERRUPTS, InterruptError, InterruptServiceRoutine};

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

pub static SYSTEM_TIMER: SystemTimer = SystemTimer::new(&DEFAULT_TIMER_HANDLER);

/// High-level system timer facade that wires the architecture timer into the
/// interrupt subsystem.
pub struct SystemTimer {
    handler: &'static DefaultTimerHandler,
    handler_registered: AtomicBool,
}

impl SystemTimer {
    const fn new(handler: &'static DefaultTimerHandler) -> Self {
        Self {
            handler,
            handler_registered: AtomicBool::new(false),
        }
    }

    /// Return the number of timer interrupts observed by the default handler.
    ///
    /// # Note
    ///
    /// The counter only increases while [`start_periodic`](Self::start_periodic) installs the
    /// default handler. Invoking this before initialisation or after swapping handlers always
    /// yields zero.
    pub fn observed_ticks(&self) -> u64 {
        self.handler.ticks.load(Ordering::Relaxed)
    }

    pub fn start_periodic(&self, ticks: TimerTicks) -> Result<(), TimerError> {
        INTERRUPTS.ensure_initialised()?;

        if ticks.raw() == 0 {
            return Err(TimerError::InvalidTicks);
        }

        self.ensure_default_handler()?;

        <Arch as ArchInterrupt>::timer().configure(TimerMode::Periodic, ticks)
    }

    pub fn stop(&self) -> Result<(), TimerError> {
        INTERRUPTS.ensure_initialised()?;
        <Arch as ArchInterrupt>::timer().stop()
    }

    fn ensure_default_handler(&self) -> Result<(), TimerError> {
        if self.handler_registered.load(Ordering::Acquire) {
            return Ok(());
        }

        if self
            .handler_registered
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }

        let vector = <Arch as ArchInterrupt>::timer_vector();
        match INTERRUPTS.register_handler(vector, self.handler) {
            Ok(()) | Err(InterruptError::HandlerAlreadyRegistered) => Ok(()),
            Err(InterruptError::InvalidVector) => {
                self.handler_registered.store(false, Ordering::Release);
                Err(TimerError::HardwareError)
            }
            Err(InterruptError::NotInitialised) => {
                self.handler_registered.store(false, Ordering::Release);
                Err(TimerError::NotInitialised)
            }
        }
    }
}
