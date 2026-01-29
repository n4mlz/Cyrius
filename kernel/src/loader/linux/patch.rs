use crate::mem::addr::{VirtAddr, VirtIntoPtr};
use crate::mem::manager;
use crate::mem::paging::{PageTableOps, PhysMapper, TranslationError};

/// Translate Linux `syscall` instructions to `int 0x80` so we can reuse the existing software
/// interrupt handler until `SYSCALL/SYSRET` is wired up.
///
/// This is a heuristic scan that may produce false positives/negatives because it does not
/// decode instruction boundaries. It uses simple byte patterns to reduce the chance of
/// rewriting immediate or displacement data.
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
            if !matches_syscall_pattern(table, addr) {
                offset = offset.saturating_add(1);
                continue;
            }
            unsafe {
                core::ptr::write(ptr, 0xCD);
                core::ptr::write(ptr.add(1), 0x80);
            }
        }
        offset = offset.saturating_add(1);
    }
    Ok(())
}

fn read_byte<T: PageTableOps>(table: &T, addr: VirtAddr) -> Result<u8, TranslationError> {
    let mapper = manager::phys_mapper();
    let phys = table.translate(addr)?;
    let ptr = unsafe { mapper.phys_to_virt(phys).into_ptr() };
    Ok(unsafe { core::ptr::read(ptr) })
}

fn matches_syscall_pattern<T: PageTableOps>(table: &T, addr: usize) -> bool {
    // Patterns anchored to the 0f 05 at `addr`.
    // - b8 imm32 0f 05
    // - 48 c7 c0 imm32 0f 05
    // - 49 c7 c0 imm32 0f 05
    // - 31 c0 b0 imm8 0f 05
    if matches_b8_imm32_syscall(table, addr) {
        return true;
    }
    if matches_rex_c7_c0_imm32_syscall(table, addr, 0x48)
        || matches_rex_c7_c0_imm32_syscall(table, addr, 0x49)
    {
        return true;
    }
    if matches_xor_eax_mov_al_syscall(table, addr) {
        return true;
    }
    if matches_syscall_followed_by_ret(table, addr) {
        return true;
    }
    if matches_stack_arg_syscall(table, addr) {
        return true;
    }
    if matches_store_load_syscall(table, addr) {
        return true;
    }
    if matches_load_to_rdi_syscall(table, addr) {
        return true;
    }
    if matches_nop_padded_syscall(table, addr) {
        return true;
    }
    false
}

fn matches_b8_imm32_syscall<T: PageTableOps>(table: &T, addr: usize) -> bool {
    if addr < 5 {
        return false;
    }
    read_byte(table, VirtAddr::new(addr - 5))
        .map(|b| b == 0xB8)
        .unwrap_or(false)
}

fn matches_rex_c7_c0_imm32_syscall<T: PageTableOps>(table: &T, addr: usize, rex: u8) -> bool {
    if addr < 7 {
        return false;
    }
    let b0 = read_byte(table, VirtAddr::new(addr - 7));
    let b1 = read_byte(table, VirtAddr::new(addr - 6));
    let b2 = read_byte(table, VirtAddr::new(addr - 5));
    matches!(b0, Ok(v) if v == rex)
        && matches!(b1, Ok(v) if v == 0xC7)
        && matches!(b2, Ok(v) if v == 0xC0)
}

fn matches_xor_eax_mov_al_syscall<T: PageTableOps>(table: &T, addr: usize) -> bool {
    if addr < 4 {
        return false;
    }
    let b0 = read_byte(table, VirtAddr::new(addr - 4));
    let b1 = read_byte(table, VirtAddr::new(addr - 3));
    let b2 = read_byte(table, VirtAddr::new(addr - 2));
    matches!(b0, Ok(v) if v == 0x31)
        && matches!(b1, Ok(v) if v == 0xC0)
        && matches!(b2, Ok(v) if v == 0xB0)
}

fn matches_syscall_followed_by_ret<T: PageTableOps>(table: &T, addr: usize) -> bool {
    let next = read_byte(table, VirtAddr::new(addr + 2));
    matches!(next, Ok(v) if v == 0xC3 || v == 0xC2)
}

fn matches_stack_arg_syscall<T: PageTableOps>(table: &T, addr: usize) -> bool {
    if addr < 8 {
        return false;
    }
    let b0 = read_byte(table, VirtAddr::new(addr - 8));
    let b1 = read_byte(table, VirtAddr::new(addr - 7));
    let b2 = read_byte(table, VirtAddr::new(addr - 6));
    let b4 = read_byte(table, VirtAddr::new(addr - 4));
    let b5 = read_byte(table, VirtAddr::new(addr - 3));
    let b6 = read_byte(table, VirtAddr::new(addr - 2));
    matches!(b0, Ok(0x48))
        && matches!(b1, Ok(0x8b))
        && matches!(b2, Ok(0x75))
        && matches!(b4, Ok(0x48))
        && matches!(b5, Ok(0x8b))
        && matches!(b6, Ok(0x55))
}

fn matches_store_load_syscall<T: PageTableOps>(table: &T, addr: usize) -> bool {
    if addr < 8 {
        return false;
    }
    let b0 = read_byte(table, VirtAddr::new(addr - 8));
    let b1 = read_byte(table, VirtAddr::new(addr - 7));
    let b2 = read_byte(table, VirtAddr::new(addr - 6));
    let b4 = read_byte(table, VirtAddr::new(addr - 4));
    let b5 = read_byte(table, VirtAddr::new(addr - 3));
    let b6 = read_byte(table, VirtAddr::new(addr - 2));
    matches!(b0, Ok(0x48))
        && matches!(b1, Ok(0x89))
        && matches!(b2, Ok(0x7d))
        && matches!(b4, Ok(0x48))
        && matches!(b5, Ok(0x8b))
        && matches!(b6, Ok(0x45))
}

fn matches_load_to_rdi_syscall<T: PageTableOps>(table: &T, addr: usize) -> bool {
    if addr < 7 {
        return false;
    }
    let b0 = read_byte(table, VirtAddr::new(addr - 7));
    let b1 = read_byte(table, VirtAddr::new(addr - 6));
    let b2 = read_byte(table, VirtAddr::new(addr - 5));
    let b4 = read_byte(table, VirtAddr::new(addr - 3));
    let b5 = read_byte(table, VirtAddr::new(addr - 2));
    let b6 = read_byte(table, VirtAddr::new(addr - 1));
    matches!(b0, Ok(0x48))
        && matches!(b1, Ok(0x8b))
        && matches!(b2, Ok(v) if v == 0x55 || v == 0x75)
        && matches!(b4, Ok(0x48))
        && matches!(b5, Ok(0x89))
        && matches!(b6, Ok(0xd7))
}

fn matches_nop_padded_syscall<T: PageTableOps>(table: &T, addr: usize) -> bool {
    if addr < 8 {
        return false;
    }
    let next = read_byte(table, VirtAddr::new(addr + 2));
    if !matches!(next, Ok(0x90)) {
        return false;
    }
    for back in 1..=8 {
        let byte = read_byte(table, VirtAddr::new(addr - back));
        if !matches!(byte, Ok(0x00)) {
            return false;
        }
    }
    true
}
