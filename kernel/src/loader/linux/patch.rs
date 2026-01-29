use crate::mem::addr::{VirtAddr, VirtIntoPtr};
use crate::mem::manager;
use crate::mem::paging::{PageTableOps, PhysMapper, TranslationError};

/// Translate Linux `syscall` instructions to `int 0x80` so we can reuse the existing software
/// interrupt handler until `SYSCALL/SYSRET` is wired up.
///
/// This is a heuristic scan that may produce false positives/negatives because it does not
/// decode instruction boundaries. It is intended as a temporary compatibility workaround.
pub fn rewrite_syscalls_in_table<T: PageTableOps>(
    base: VirtAddr,
    size: usize,
    table: &T,
) -> Result<(), TranslationError> {
    let mapper = manager::phys_mapper();
    let mut offset = 0usize;
    while offset + 1 < size {
        let addr = match base.as_raw().checked_add(offset) {
            Some(addr) => addr,
            None => return Err(TranslationError::NotMapped),
        };
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
