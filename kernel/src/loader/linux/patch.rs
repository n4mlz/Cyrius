use crate::mem::addr::VirtIntoPtr;

use super::elf::ProgramSegment;

/// Translate Linux `syscall` instructions to `int 0x80` so we can reuse the existing software
/// interrupt handler until `SYSCALL/SYSRET` is wired up.
pub fn rewrite_syscalls(seg: &ProgramSegment) {
    let mut offset = 0usize;
    while offset + 1 < seg.file_size {
        let ptr = unsafe { seg.vaddr.into_mut_ptr().add(offset) };
        let opcode = unsafe { core::ptr::read(ptr) };
        let next = unsafe { core::ptr::read(ptr.add(1)) };
        if opcode == 0x0F && next == 0x05 {
            unsafe {
                core::ptr::write(ptr, 0xCD);
                core::ptr::write(ptr.add(1), 0x80);
            }
        }
        offset = offset.saturating_add(1);
    }
}
