use core::sync::atomic::{AtomicBool, Ordering};

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

static HANDLER_SET: AtomicBool = AtomicBool::new(false);
static mut HANDLER: Option<&'static dyn TrapHandler> = None;

struct LoggingTrapHandler;

static LOGGING_HANDLER: LoggingTrapHandler = LoggingTrapHandler;

pub fn register_handler(handler: &'static dyn TrapHandler) {
    if !try_register(handler) {
        panic!("trap handler already registered");
    }
}

pub fn init() {
    ensure_default_handler();
    Arch::init_traps();
}

pub(crate) fn dispatch(info: TrapInfo, frame: &mut CurrentTrapFrame) {
    if let Some(handler) = unsafe { HANDLER } {
        handler.handle_trap(info, frame);
    } else {
        println!(
            "[trap] vector={} origin={:?} desc={} (no handler)",
            info.vector, info.origin, info.description
        );
        println!("[trap] frame={:#?}", frame);
    }
}

fn ensure_default_handler() {
    if HANDLER_SET.load(Ordering::SeqCst) {
        return;
    }
    let _ = try_register(&LOGGING_HANDLER);
}

fn try_register(handler: &'static dyn TrapHandler) -> bool {
    if HANDLER_SET
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        unsafe {
            HANDLER = Some(handler);
        }
        true
    } else {
        false
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
