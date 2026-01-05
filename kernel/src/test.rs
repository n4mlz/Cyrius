use crate::{print, println};

pub use kernel_macros::kernel_test_case;

#[repr(C)]
pub struct NamedTest {
    pub name: &'static str,
}

#[allow(improper_ctypes)]
unsafe extern "C" {
    static __start_cyrius_tests: NamedTest;
    static __stop_cyrius_tests: NamedTest;
}

#[derive(Clone, Copy, Debug)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x20,
    Failed = 0x22,
}

pub fn run_tests(tests: &[&dyn Fn()]) {
    let name_filter = selected_name_filter();
    let list_only = option_env!("CYRIUS_TEST_LIST_ONLY").is_some();

    let metadata = named_tests();
    if metadata.len() != tests.len() {
        println!(
            "[test] warning: metadata/test count mismatch ({} vs {})",
            metadata.len(),
            tests.len()
        );
    }

    println!("[test] discovered {} case(s)", tests.len());

    let mut matched = 0usize;

    for (index, test) in tests.iter().enumerate() {
        let name = metadata
            .get(index)
            .map(|entry| entry.name)
            .unwrap_or("<unnamed>");

        if let Some(pattern) = name_filter
            && !name.contains(pattern)
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
        if let Some(pattern) = name_filter
            && matched == 0
        {
            println!("[test] no test matched pattern '{pattern}'");
            exit_qemu(QemuExitCode::Failed);
        }
        println!("[test] listed {matched} matching case(s)");
        exit_qemu(QemuExitCode::Success);
    }

    if matched == 0 {
        if let Some(pattern) = name_filter {
            println!("[test] no test matched pattern '{pattern}'");
        } else {
            println!("[test] no tests executed");
        }
        exit_qemu(QemuExitCode::Failed);
    }

    println!("[test] all {matched} case(s) passed");
    exit_qemu(QemuExitCode::Success);
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

fn named_tests() -> &'static [NamedTest] {
    unsafe {
        let start = core::ptr::addr_of!(__start_cyrius_tests);
        let end = core::ptr::addr_of!(__stop_cyrius_tests);
        let len = end.offset_from(start) as usize;
        core::slice::from_raw_parts(start, len)
    }
}

fn selected_name_filter() -> Option<&'static str> {
    match option_env!("CYRIUS_TEST_FILTER_KIND") {
        Some("name") => {
            option_env!("CYRIUS_TEST_FILTER_VALUE").filter(|pattern| !pattern.is_empty())
        }
        _ => None,
    }
}
