use core::arch::asm;

use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

/// Enable the floating-point/SSE execution environment so user binaries can
/// execute XMM instructions without #UD/#NM faults.
pub(super) fn init_features() {
    enable_sse_and_fpu();
}

fn enable_sse_and_fpu() {
    unsafe {
        let mut cr0 = Cr0::read();
        cr0.remove(Cr0Flags::EMULATE_COPROCESSOR);
        cr0.insert(Cr0Flags::MONITOR_COPROCESSOR);
        cr0.insert(Cr0Flags::NUMERIC_ERROR);
        cr0.remove(Cr0Flags::TASK_SWITCHED);
        Cr0::write(cr0);

        let mut cr4 = Cr4::read();
        cr4.insert(Cr4Flags::OSFXSR);
        cr4.insert(Cr4Flags::OSXMMEXCPT_ENABLE);
        Cr4::write(cr4);

        asm!("fninit", options(nostack));
    }
}
