use crate::mem::addr::{VirtAddr, VirtIntoPtr};
use crate::mem::manager;
use crate::mem::paging::{PageTableOps, PhysMapper, TranslationError};

use super::elf::ProgramSegment;

/// Translate Linux `syscall` instructions to `int 0x80` so we can reuse the existing software
/// interrupt handler until `SYSCALL/SYSRET` is wired up.
pub fn rewrite_syscalls_in_table<T: PageTableOps>(
    seg: &ProgramSegment,
    table: &T,
) -> Result<(), TranslationError> {
    let mapper = manager::phys_mapper();
    let mut offset = 0usize;
    while offset + 1 < seg.file_size {
        let addr = seg.vaddr.as_raw() + offset;
        let virt = VirtAddr::new(addr);
        let phys = table.translate(virt)?;
        let ptr = unsafe { mapper.phys_to_virt(phys).into_mut_ptr() };
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
    Ok(())
}
