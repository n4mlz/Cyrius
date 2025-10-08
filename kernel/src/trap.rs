use core::sync::atomic::{AtomicBool, Ordering};

use crate::util::{lazylock::LazyLock, spinlock::SpinLock};

use crate::arch::{Arch, api::ArchTrap};
use crate::{print, println};

pub trait TrapFrame: core::fmt::Debug {
    fn error_code(&self) -> Option<u64> {
        None
    }
}

pub type CurrentTrapFrame = <Arch as ArchTrap>::Frame;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrapOrigin {
    Exception,
    Interrupt,
    NonMaskable,
    Unknown,
}

#[derive(Clone, Copy, Debug)]
pub struct TrapInfo {
    pub vector: u8,
    pub origin: TrapOrigin,
    pub description: &'static str,
    pub has_error_code: bool,
}

pub trait TrapHandler: Sync {
    fn handle_trap(&self, info: TrapInfo, frame: &mut CurrentTrapFrame);
}

static TRAP_INITIALISED: AtomicBool = AtomicBool::new(false);

type HandlerSlot = SpinLock<Option<&'static dyn TrapHandler>>;
type HandlerFactory = fn() -> HandlerSlot;

const fn handler_slot() -> HandlerSlot {
    SpinLock::new(None)
}

static HANDLER: LazyLock<HandlerSlot, HandlerFactory> = LazyLock::new_const(handler_slot);

struct LoggingTrapHandler;

static LOGGING_HANDLER: LoggingTrapHandler = LoggingTrapHandler;

/// Install a global trap handler. Replaces the default logging handler but refuses
/// to overwrite a previously registered custom handler.
pub fn register_handler(handler: &'static dyn TrapHandler) {
    let mut slot = HANDLER.lock();
    match slot.as_ref() {
        Some(current) if core::ptr::eq(*current, handler) => {}
        Some(current) if core::ptr::eq(*current, &LOGGING_HANDLER) => {
            *slot = Some(handler);
        }
        Some(_) => panic!("trap handler already registered"),
        None => *slot = Some(handler),
    }
}

/// Initialise architecture-specific trap tables. Safe to call multiple times.
pub fn init() {
    ensure_default_handler();
    if TRAP_INITIALISED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        Arch::init_traps();
    }
}

pub(crate) fn dispatch(info: TrapInfo, frame: &mut CurrentTrapFrame) {
    let handler = {
        let slot = HANDLER.lock();
        *slot
    };
    handler.unwrap_or(&LOGGING_HANDLER).handle_trap(info, frame);
}

fn ensure_default_handler() {
    let mut slot = HANDLER.lock();
    if slot.is_none() {
        *slot = Some(&LOGGING_HANDLER);
    }
}

impl TrapHandler for LoggingTrapHandler {
    fn handle_trap(&self, info: TrapInfo, frame: &mut CurrentTrapFrame) {
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
