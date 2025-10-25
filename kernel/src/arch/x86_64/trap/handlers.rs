use x86_64::registers::control::Cr2;

use crate::println;
use crate::trap::TrapInfo;

use super::TrapFrame;

pub fn handle_exception(info: TrapInfo, frame: &mut TrapFrame) -> bool {
    match info.vector {
        14 => {
            handle_page_fault(frame);
            true
        }
        13 => {
            handle_general_protection(frame);
            true
        }
        8 => {
            handle_double_fault(frame);
            true
        }
        _ => false,
    }
}

fn handle_page_fault(frame: &TrapFrame) {
    let fault_addr = Cr2::read().expect("CR2 must contain a canonical address");
    let code = frame.error_code;

    let present = (code & 1) != 0;
    let write = (code & 1 << 1) != 0;
    let user = (code & 1 << 2) != 0;
    let reserved = (code & 1 << 3) != 0;
    let instruction = (code & 1 << 4) != 0;

    println!(
        "[#PF] fault_addr={:#x} present={} write={} user={} reserved={} instruction={}",
        fault_addr.as_u64(),
        present,
        write,
        user,
        reserved,
        instruction
    );
    println!("[#PF] frame={:#?}", frame);
    panic!("page fault while executing in kernel context");
}

fn handle_general_protection(frame: &TrapFrame) {
    println!("[#GP] error_code={:#x}", frame.error_code);
    println!("[#GP] frame={:#?}", frame);
    panic!("general protection fault");
}

fn handle_double_fault(frame: &TrapFrame) {
    println!("[#DF] double fault encountered");
    println!("[#DF] frame={:#?}", frame);
    panic!("double fault");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86_64::trap::context::GeneralRegisters;
    use crate::test::kernel_test_case;
    use crate::trap::TrapOrigin;

    #[kernel_test_case]
    fn other_vectors_fall_back() {
        let info = TrapInfo {
            vector: 0x21,
            origin: TrapOrigin::Exception,
            description: "test",
            has_error_code: false,
        };
        let mut frame = TrapFrame {
            error_code: 0,
            regs: GeneralRegisters::zero(),
            rip: 0,
            cs: 0,
            rflags: 0,
            rsp: 0,
            ss: 0,
        };

        assert!(!handle_exception(info, &mut frame));
    }
}
