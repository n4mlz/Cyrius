use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::{
    Arch,
    api::{ArchInterrupt, TimerDriver, TimerError, TimerMode, TimerTicks},
};
use crate::println;
use crate::trap::{CurrentTrapFrame, TrapInfo};
use crate::util::spinlock::SpinLock;

use super::{INTERRUPTS, InterruptError, InterruptServiceRoutine};

pub static SYSTEM_TIMER: SystemTimer = SystemTimer::new();
static TIMER_DISPATCH: TimerDispatch = TimerDispatch;

struct TimerDispatch;

/// High-level system timer facade that wires the architecture timer into the
/// interrupt subsystem.
pub struct SystemTimer {
    handler_registered: AtomicBool,
    observed: AtomicU64,
    delegate: SpinLock<Option<&'static dyn InterruptServiceRoutine>>,
}

impl SystemTimer {
    const fn new() -> Self {
        Self {
            handler_registered: AtomicBool::new(false),
            observed: AtomicU64::new(0),
            delegate: SpinLock::new(None),
        }
    }

    /// Return the number of timer interrupts observed by the default handler.
    ///
    /// # Note
    ///
    /// The counter increases for every timer interrupt regardless of whether a custom handler is
    /// installed. This mirrors the LAPIC tick count observable prior to the scheduler taking over
    /// the interrupt.
    pub fn observed_ticks(&self) -> u64 {
        self.observed.load(Ordering::Relaxed)
    }

    pub fn start_periodic(&self, ticks: TimerTicks) -> Result<(), TimerError> {
        INTERRUPTS.ensure_initialised()?;

        if ticks.raw() == 0 {
            return Err(TimerError::InvalidTicks);
        }

        self.ensure_dispatch_handler()?;

        <Arch as ArchInterrupt>::timer().configure(TimerMode::Periodic, ticks)
    }

    pub fn stop(&self) -> Result<(), TimerError> {
        INTERRUPTS.ensure_initialised()?;
        <Arch as ArchInterrupt>::timer().stop()
    }

    /// Install a custom interrupt handler to be invoked after bookkeeping completes.
    pub fn install_handler(
        &self,
        handler: &'static dyn InterruptServiceRoutine,
    ) -> Result<(), TimerError> {
        INTERRUPTS.ensure_initialised()?;
        self.ensure_dispatch_handler()?;

        let mut slot = self.delegate.lock();
        *slot = Some(handler);
        Ok(())
    }

    /// Remove the currently registered custom handler, reverting to the default behaviour.
    pub fn clear_handler(&self) {
        let mut slot = self.delegate.lock();
        *slot = None;
    }

    fn ensure_dispatch_handler(&self) -> Result<(), TimerError> {
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
        match INTERRUPTS.register_handler(vector, &TIMER_DISPATCH) {
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
    fn handle_interrupt(&self, info: TrapInfo, frame: &mut CurrentTrapFrame) {
        let previous = self.observed.fetch_add(1, Ordering::Relaxed);
        if previous == 0 {
            println!("[timer] first tick");
        }

        let handler = {
            let slot = self.delegate.lock();
            *slot
        };

        if let Some(handler) = handler {
            handler.handle(info, frame);
        }

        // Ensure the compiler keeps `info`/`frame` used until here even if delegate is absent.
        let _ = info;
        let _ = frame;
    }
}

impl InterruptServiceRoutine for TimerDispatch {
    fn handle(&self, info: TrapInfo, frame: &mut CurrentTrapFrame) {
        SYSTEM_TIMER.handle_interrupt(info, frame);
    }
}
