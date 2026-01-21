use alloc::vec::Vec;
use core::mem::size_of;

use crate::mem::addr::{Addr, PageSize, VirtAddr, VirtIntoPtr, align_down};
use crate::mem::manager;
use crate::mem::paging::{PageTableOps, PhysMapper, TranslationError};

#[derive(Clone, Copy)]
pub struct AuxvEntry {
    pub key: u64,
    pub value: u64,
}

#[derive(Debug)]
pub enum StackBuildError {
    Overflow,
    NotMapped,
    UnsupportedPageSize,
}

pub fn initialise_minimal_stack(stack_top: VirtAddr) -> VirtAddr {
    let mut sp = align_down(stack_top.as_raw(), 16);

    // auxv terminator
    sp -= size_of::<u64>();
    unsafe { *(sp as *mut u64) = 0 };
    sp -= size_of::<u64>();
    unsafe { *(sp as *mut u64) = 0 };

    // envp null
    sp -= size_of::<u64>();
    unsafe { *(sp as *mut u64) = 0 };

    // argv null
    sp -= size_of::<u64>();
    unsafe { *(sp as *mut u64) = 0 };

    // argc = 0
    sp -= size_of::<u64>();
    unsafe { *(sp as *mut u64) = 0 };

    VirtAddr::new(sp)
}

pub fn initialise_minimal_stack_in_table<T: PageTableOps>(
    table: &T,
    stack_top: VirtAddr,
) -> Result<VirtAddr, StackBuildError> {
    let mut sp = align_down(stack_top.as_raw(), 16);

    sp -= size_of::<u64>();
    write_u64_in_table(table, VirtAddr::new(sp), 0)?;
    sp -= size_of::<u64>();
    write_u64_in_table(table, VirtAddr::new(sp), 0)?;

    sp -= size_of::<u64>();
    write_u64_in_table(table, VirtAddr::new(sp), 0)?;

    sp -= size_of::<u64>();
    write_u64_in_table(table, VirtAddr::new(sp), 0)?;

    sp -= size_of::<u64>();
    write_u64_in_table(table, VirtAddr::new(sp), 0)?;

    Ok(VirtAddr::new(sp))
}

pub fn initialise_stack_with_args(
    stack_top: VirtAddr,
    argv: &[&str],
    envp: &[&str],
    auxv: &[AuxvEntry],
) -> Result<VirtAddr, StackBuildError> {
    let mut sp = align_down(stack_top.as_raw(), 16);
    let mut argv_ptrs = Vec::with_capacity(argv.len());
    let mut envp_ptrs = Vec::with_capacity(envp.len());

    for arg in argv.iter().rev() {
        let ptr = push_cstring(&mut sp, arg.as_bytes())?;
        argv_ptrs.push(ptr as u64);
    }
    for env in envp.iter().rev() {
        let ptr = push_cstring(&mut sp, env.as_bytes())?;
        envp_ptrs.push(ptr as u64);
    }

    sp = align_down(sp, 16);

    // auxv (terminate with AT_NULL)
    push_u64(&mut sp, 0)?;
    push_u64(&mut sp, 0)?;
    for entry in auxv.iter().rev() {
        push_u64(&mut sp, entry.value)?;
        push_u64(&mut sp, entry.key)?;
    }

    // envp pointers
    push_u64(&mut sp, 0)?;
    for ptr in envp_ptrs.iter() {
        push_u64(&mut sp, *ptr)?;
    }

    // argv pointers
    push_u64(&mut sp, 0)?;
    for ptr in argv_ptrs.iter() {
        push_u64(&mut sp, *ptr)?;
    }

    // argc
    push_u64(&mut sp, argv.len() as u64)?;

    Ok(VirtAddr::new(sp))
}

pub fn initialise_stack_with_args_in_table<T: PageTableOps>(
    table: &T,
    stack_top: VirtAddr,
    argv: &[&str],
    envp: &[&str],
    auxv: &[AuxvEntry],
) -> Result<VirtAddr, StackBuildError> {
    let mut sp = align_down(stack_top.as_raw(), 16);
    let mut argv_ptrs = Vec::with_capacity(argv.len());
    let mut envp_ptrs = Vec::with_capacity(envp.len());

    for arg in argv.iter().rev() {
        let ptr = push_cstring_in_table(table, &mut sp, arg.as_bytes())?;
        argv_ptrs.push(ptr as u64);
    }
    for env in envp.iter().rev() {
        let ptr = push_cstring_in_table(table, &mut sp, env.as_bytes())?;
        envp_ptrs.push(ptr as u64);
    }

    sp = align_down(sp, 16);

    push_u64_in_table(table, &mut sp, 0)?;
    push_u64_in_table(table, &mut sp, 0)?;
    for entry in auxv.iter().rev() {
        push_u64_in_table(table, &mut sp, entry.value)?;
        push_u64_in_table(table, &mut sp, entry.key)?;
    }

    push_u64_in_table(table, &mut sp, 0)?;
    for ptr in envp_ptrs.iter() {
        push_u64_in_table(table, &mut sp, *ptr)?;
    }

    push_u64_in_table(table, &mut sp, 0)?;
    for ptr in argv_ptrs.iter() {
        push_u64_in_table(table, &mut sp, *ptr)?;
    }

    push_u64_in_table(table, &mut sp, argv.len() as u64)?;

    Ok(VirtAddr::new(sp))
}

fn push_cstring(sp: &mut usize, bytes: &[u8]) -> Result<usize, StackBuildError> {
    let len = bytes
        .len()
        .checked_add(1)
        .ok_or(StackBuildError::Overflow)?;
    *sp = sp.checked_sub(len).ok_or(StackBuildError::Overflow)?;
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), *sp as *mut u8, bytes.len());
        *(*sp as *mut u8).add(bytes.len()) = 0;
    }
    Ok(*sp)
}

fn push_cstring_in_table<T: PageTableOps>(
    table: &T,
    sp: &mut usize,
    bytes: &[u8],
) -> Result<usize, StackBuildError> {
    let len = bytes
        .len()
        .checked_add(1)
        .ok_or(StackBuildError::Overflow)?;
    *sp = sp.checked_sub(len).ok_or(StackBuildError::Overflow)?;
    let addr = VirtAddr::new(*sp);
    write_bytes_in_table(table, addr, bytes)?;
    write_bytes_in_table(
        table,
        addr.checked_add(bytes.len())
            .ok_or(StackBuildError::Overflow)?,
        &[0],
    )?;
    Ok(*sp)
}

fn push_u64(sp: &mut usize, value: u64) -> Result<(), StackBuildError> {
    *sp = sp
        .checked_sub(size_of::<u64>())
        .ok_or(StackBuildError::Overflow)?;
    unsafe {
        *(*sp as *mut u64) = value;
    }
    Ok(())
}

fn push_u64_in_table<T: PageTableOps>(
    table: &T,
    sp: &mut usize,
    value: u64,
) -> Result<(), StackBuildError> {
    *sp = sp
        .checked_sub(size_of::<u64>())
        .ok_or(StackBuildError::Overflow)?;
    write_u64_in_table(table, VirtAddr::new(*sp), value)
}

fn write_u64_in_table<T: PageTableOps>(
    table: &T,
    addr: VirtAddr,
    value: u64,
) -> Result<(), StackBuildError> {
    write_bytes_in_table(table, addr, &value.to_le_bytes())
}

fn write_bytes_in_table<T: PageTableOps>(
    table: &T,
    addr: VirtAddr,
    bytes: &[u8],
) -> Result<(), StackBuildError> {
    // User stacks are populated while running on the kernel page table.
    let mapper = manager::phys_mapper();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let raw = addr
            .as_raw()
            .checked_add(offset)
            .ok_or(StackBuildError::Overflow)?;
        let virt = VirtAddr::new(raw);
        let phys = table.translate(virt).map_err(StackBuildError::from)?;
        let page_offset = raw % PageSize::SIZE_4K.bytes();
        let len = (PageSize::SIZE_4K.bytes() - page_offset).min(bytes.len() - offset);
        unsafe {
            let ptr = mapper.phys_to_virt(phys);
            core::ptr::copy_nonoverlapping(bytes[offset..].as_ptr(), ptr.into_mut_ptr(), len);
        }
        offset += len;
    }
    Ok(())
}

impl From<TranslationError> for StackBuildError {
    fn from(err: TranslationError) -> Self {
        match err {
            TranslationError::NotMapped => StackBuildError::NotMapped,
            TranslationError::HugePage => StackBuildError::UnsupportedPageSize,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::addr::VirtAddr;
    use crate::println;
    use crate::test::kernel_test_case;

    #[kernel_test_case]
    fn builds_stack_with_args() {
        println!("[test] builds_stack_with_args");

        let mut buf = [0u8; 1024];
        let top = VirtAddr::new(buf.as_mut_ptr() as usize + buf.len());
        let argv = ["sh", "-c"];
        let envp = ["PATH=/bin"];
        let auxv = [AuxvEntry {
            key: 6,
            value: 4096,
        }];

        let sp = initialise_stack_with_args(top, &argv, &envp, &auxv).expect("stack build");
        let mut cursor = sp.as_raw() as *const u64;

        unsafe {
            let argc = *cursor;
            assert_eq!(argc, 2);
            cursor = cursor.add(1);

            let argv0 = *cursor as *const u8;
            let argv1 = *cursor.add(1) as *const u8;
            assert_eq!(read_cstring(argv0), "sh");
            assert_eq!(read_cstring(argv1), "-c");
            cursor = cursor.add(2);
            assert_eq!(*cursor, 0);
            cursor = cursor.add(1);

            let env0 = *cursor as *const u8;
            assert_eq!(read_cstring(env0), "PATH=/bin");
            cursor = cursor.add(1);
            assert_eq!(*cursor, 0);
        }
    }

    unsafe fn read_cstring(ptr: *const u8) -> alloc::string::String {
        let mut len = 0usize;
        unsafe {
            while *ptr.add(len) != 0 {
                len += 1;
            }
            let slice = core::slice::from_raw_parts(ptr, len);
            alloc::string::String::from_utf8_lossy(slice).into_owned()
        }
    }
}
