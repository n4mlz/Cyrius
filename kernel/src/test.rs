use crate::{print, println};

#[derive(Clone, Copy, Debug)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x20,
    Failed = 0x22,
}

pub fn run_tests(tests: &[&dyn Fn()]) {
    let selector = selected_case_index();
    let list_only = option_env!("CYRIUS_TEST_LIST_ONLY").is_some();

    println!("[test] discovered {} case(s)", tests.len());

    let mut matched = 0usize;

    for (index, test) in tests.iter().enumerate() {
        if let Some(target) = selector
            && index != target
        {
            continue;
        }

        if list_only {
            println!("[test] case #{index}");
            matched += 1;
            continue;
        }

        print!("[test] case #{index} ... ");
        test();
        println!("ok");
        matched += 1;
    }

    if list_only {
        if let Some(target) = selector
            && matched == 0
        {
            println!("[test] requested case #{target} not found");
            exit_qemu(QemuExitCode::Failed);
        }
        println!("[test] listed {matched} matching case(s)");
        exit_qemu(QemuExitCode::Success);
    }

    if let Some(target) = selector
        && matched == 0
    {
        println!("[test] requested case #{target} not found");
        exit_qemu(QemuExitCode::Failed);
    }

    if matched == 0 {
        println!("[test] no tests executed");
        exit_qemu(QemuExitCode::Failed);
    }

    println!("[test] all {matched} case(s) passed");
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

fn selected_case_index() -> Option<usize> {
    match (
        option_env!("CYRIUS_TEST_FILTER_KIND"),
        option_env!("CYRIUS_TEST_FILTER_VALUE"),
    ) {
        (Some("index"), Some(raw)) => raw.parse().ok(),
        _ => None,
    }
}
