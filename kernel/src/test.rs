use crate::{print, println};

#[derive(Clone, Copy, Debug)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

pub fn run_tests(tests: &[&dyn Fn()]) {
    println!("[test] running {} case(s)", tests.len());
    for (index, test) in tests.iter().enumerate() {
        print!("[test] case #{index} ... ");
        test();
        println!("ok");
    }
    println!("[test] all cases passed");
}

pub fn exit_qemu(code: QemuExitCode) -> ! {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        use x86_64::instructions::port::PortWriteOnly;
        let mut port = PortWriteOnly::<u32>::new(0xF4);
        port.write(code as u32);
    }

    loop {
        core::hint::spin_loop()
    }
}
