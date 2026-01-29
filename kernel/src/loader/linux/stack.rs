use alloc::vec::Vec;
use core::mem::size_of;

use crate::mem::addr::{Addr, VirtAddr, align_down};
use crate::mem::paging::PageTableOps;
use crate::mem::user::{UserAccessError, UserMemoryAccess};

use super::AT_RANDOM;

const AT_RANDOM_LEN: usize = 16;

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

/// Build a minimal stack that is not Linux ABI-complete; intended for simple tests only.
pub fn initialise_minimal_stack<T: PageTableOps>(
    table: &T,
    stack_top: VirtAddr,
) -> Result<VirtAddr, StackBuildError> {
    let mut sp = align_down(stack_top.as_raw(), 16);
    let user = UserMemoryAccess::new(table);

    sp -= size_of::<u64>();
    user.write_u64(VirtAddr::new(sp), 0)
        .map_err(StackBuildError::from)?;
    sp -= size_of::<u64>();
    user.write_u64(VirtAddr::new(sp), 0)
        .map_err(StackBuildError::from)?;

    sp -= size_of::<u64>();
    user.write_u64(VirtAddr::new(sp), 0)
        .map_err(StackBuildError::from)?;

    sp -= size_of::<u64>();
    user.write_u64(VirtAddr::new(sp), 0)
        .map_err(StackBuildError::from)?;

    sp -= size_of::<u64>();
    user.write_u64(VirtAddr::new(sp), 0)
        .map_err(StackBuildError::from)?;

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

    // TODO: Replace zeroed bytes with a kernel RNG once available.
    let random_ptr = {
        sp = sp.checked_sub(AT_RANDOM_LEN).ok_or(StackBuildError::Overflow)?;
        unsafe {
            core::ptr::write_bytes(sp as *mut u8, 0, AT_RANDOM_LEN);
        }
        sp as u64
    };

    let mut auxv_entries: Vec<AuxvEntry> = auxv.to_vec();
    if !auxv_entries.iter().any(|entry| entry.key == AT_RANDOM) {
        auxv_entries.push(AuxvEntry {
            key: AT_RANDOM,
            value: random_ptr,
        });
    }

    sp = align_down(sp, 16);

    push_u64(&mut sp, 0)?;
    push_u64(&mut sp, 0)?;
    for entry in auxv_entries.iter().rev() {
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
    let user = UserMemoryAccess::new(table);

    for arg in argv.iter().rev() {
        let ptr = push_cstring_in_table(&user, &mut sp, arg.as_bytes())?;
        argv_ptrs.push(ptr as u64);
    }
    for env in envp.iter().rev() {
        let ptr = push_cstring_in_table(&user, &mut sp, env.as_bytes())?;
        envp_ptrs.push(ptr as u64);
    }

    sp = align_down(sp, 16);

    // TODO: Replace zeroed bytes with a kernel RNG once available.
    let random_ptr = {
        sp = sp.checked_sub(AT_RANDOM_LEN).ok_or(StackBuildError::Overflow)?;
        let addr = VirtAddr::new(sp);
        let zeros = [0u8; AT_RANDOM_LEN];
        user.write_bytes(addr, &zeros)
            .map_err(StackBuildError::from)?;
        sp as u64
    };

    let mut auxv_entries: Vec<AuxvEntry> = auxv.to_vec();
    if !auxv_entries.iter().any(|entry| entry.key == AT_RANDOM) {
        auxv_entries.push(AuxvEntry {
            key: AT_RANDOM,
            value: random_ptr,
        });
    }

    sp = align_down(sp, 16);

    push_u64_in_table(&user, &mut sp, 0)?;
    push_u64_in_table(&user, &mut sp, 0)?;
    for entry in auxv_entries.iter().rev() {
        push_u64_in_table(&user, &mut sp, entry.value)?;
        push_u64_in_table(&user, &mut sp, entry.key)?;
    }

    push_u64_in_table(&user, &mut sp, 0)?;
    for ptr in envp_ptrs.iter() {
        push_u64_in_table(&user, &mut sp, *ptr)?;
    }

    push_u64_in_table(&user, &mut sp, 0)?;
    for ptr in argv_ptrs.iter() {
        push_u64_in_table(&user, &mut sp, *ptr)?;
    }

    push_u64_in_table(&user, &mut sp, argv.len() as u64)?;

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
    user: &UserMemoryAccess<'_, T>,
    sp: &mut usize,
    bytes: &[u8],
) -> Result<usize, StackBuildError> {
    let len = bytes
        .len()
        .checked_add(1)
        .ok_or(StackBuildError::Overflow)?;
    *sp = sp.checked_sub(len).ok_or(StackBuildError::Overflow)?;
    let addr = VirtAddr::new(*sp);
    user.write_bytes(addr, bytes)
        .map_err(StackBuildError::from)?;
    user.write_bytes(
        addr.checked_add(bytes.len())
            .ok_or(StackBuildError::Overflow)?,
        &[0],
    )
    .map_err(StackBuildError::from)?;
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
    user: &UserMemoryAccess<'_, T>,
    sp: &mut usize,
    value: u64,
) -> Result<(), StackBuildError> {
    *sp = sp
        .checked_sub(size_of::<u64>())
        .ok_or(StackBuildError::Overflow)?;
    user.write_u64(VirtAddr::new(*sp), value)
        .map_err(StackBuildError::from)
}

impl From<UserAccessError> for StackBuildError {
    fn from(err: UserAccessError) -> Self {
        match err {
            UserAccessError::NotMapped => StackBuildError::NotMapped,
            UserAccessError::UnsupportedPageSize => StackBuildError::UnsupportedPageSize,
            UserAccessError::AddressOverflow => StackBuildError::Overflow,
            UserAccessError::NullPointer
            | UserAccessError::NonCanonical
            | UserAccessError::OutOfRange
            | UserAccessError::Misaligned { .. }
            | UserAccessError::ZeroSizedType => StackBuildError::Overflow,
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
