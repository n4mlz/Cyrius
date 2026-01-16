use crate::println;
use crate::trap::{CurrentTrapFrame, TrapFrame, TrapInfo};

pub trait TrapLogger: Sync {
    fn log_unhandled_interrupt(&self, info: TrapInfo);
    fn log_trap(&self, info: TrapInfo, frame: &mut CurrentTrapFrame);
}

pub struct DefaultTrapLogger;

impl TrapLogger for DefaultTrapLogger {
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

pub static DEFAULT_TRAP_LOGGER: DefaultTrapLogger = DefaultTrapLogger;
