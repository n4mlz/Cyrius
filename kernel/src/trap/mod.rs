use core::hint::spin_loop;

use crate::arch::api::{ArchTrapController, TrapInfo};
use crate::arch::{
    Arch,
    api::{ArchPlatform, TrapHandler},
};
use crate::{print, println};

pub use crate::arch::api::{TrapFrame, TrapKind, TrapOrigin};

struct LoggingTrapHandler;

static LOGGING_HANDLER: LoggingTrapHandler = LoggingTrapHandler;

pub fn init() {
    install_handler(&LOGGING_HANDLER);
}

pub fn install_handler(
    handler: &'static dyn TrapHandler<Frame = <Arch as ArchPlatform>::TrapFrame>,
) {
    Arch::traps().init(handler);
}

impl TrapHandler for LoggingTrapHandler {
    type Frame = <Arch as ArchPlatform>::TrapFrame;

    fn handle_trap(&self, frame: &mut Self::Frame, info: TrapInfo) {
        println!(
            "trap: vector={} origin={:?} kind={:?} desc={} error={:?} fault={:?}",
            info.vector,
            info.origin,
            info.kind,
            info.description,
            info.error_code,
            info.fault_address,
        );
        println!("frame: {:?}", frame);
        loop {
            spin_loop();
        }
    }
}
