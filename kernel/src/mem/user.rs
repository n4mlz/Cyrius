//! User-space memory helpers.
//!
//! # Architecture Assumptions
//! These routines assume four-level (48-bit) x86_64 canonical addresses. Once LA57 support is
//! introduced the range checks must be revised accordingly.
use core::mem::size_of;
use core::ptr::copy_nonoverlapping;

use crate::mem::addr::{Addr, VirtAddr, VirtIntoPtr};

const USER_SPACE_LIMIT: usize = 0x0000_8000_0000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserAccessError {
    NullPointer,
    NonCanonical,
    AddressOverflow,
    OutOfRange,
    Misaligned { alignment: usize },
    ZeroSizedType,
}

pub fn copy_to_user(user_dst: VirtAddr, src: &[u8]) -> Result<(), UserAccessError> {
    if src.is_empty() {
        return Ok(());
    }

    let len = src.len();
    validate_user_range(user_dst, len)?;

    unsafe {
        copy_nonoverlapping(src.as_ptr(), user_dst.into_mut_ptr(), len);
    }
    Ok(())
}

pub fn copy_from_user(dst: &mut [u8], user_src: VirtAddr) -> Result<(), UserAccessError> {
    if dst.is_empty() {
        return Ok(());
    }

    let len = dst.len();
    validate_user_range(user_src, len)?;

    unsafe {
        copy_nonoverlapping(user_src.into_ptr(), dst.as_mut_ptr(), len);
    }
    Ok(())
}

pub fn with_user_slice<T, F, R>(ptr: VirtAddr, len: usize, f: F) -> Result<R, UserAccessError>
where
    F: FnOnce(&[T]) -> R,
{
    guard_zero_sized::<T>()?;
    let total = total_bytes::<T>(len)?;
    validate_user_range(ptr, total)?;
    ensure_alignment::<T>(ptr)?;

    let slice = unsafe { core::slice::from_raw_parts(ptr.into_ptr() as *const T, len) };
    Ok(f(slice))
}

pub fn with_user_slice_mut<T, F, R>(ptr: VirtAddr, len: usize, f: F) -> Result<R, UserAccessError>
where
    F: FnOnce(&mut [T]) -> R,
{
    guard_zero_sized::<T>()?;
    let total = total_bytes::<T>(len)?;
    validate_user_range(ptr, total)?;
    ensure_alignment::<T>(ptr)?;

    let slice = unsafe { core::slice::from_raw_parts_mut(ptr.into_mut_ptr() as *mut T, len) };
    Ok(f(slice))
}

fn validate_user_range(addr: VirtAddr, len: usize) -> Result<(), UserAccessError> {
    if len == 0 {
        return Ok(());
    }

    let raw = addr.as_raw();
    if raw == 0 {
        return Err(UserAccessError::NullPointer);
    }

    if raw >= USER_SPACE_LIMIT {
        return Err(UserAccessError::OutOfRange);
    }

    let end = raw
        .checked_add(len)
        .ok_or(UserAccessError::AddressOverflow)?;
    if end > USER_SPACE_LIMIT {
        return Err(UserAccessError::OutOfRange);
    }

    if !is_lower_canonical(raw) {
        return Err(UserAccessError::NonCanonical);
    }

    Ok(())
}

fn ensure_alignment<T>(addr: VirtAddr) -> Result<(), UserAccessError> {
    let align = core::mem::align_of::<T>();
    if align > 1 && !addr.is_aligned(align) {
        return Err(UserAccessError::Misaligned { alignment: align });
    }
    Ok(())
}

fn guard_zero_sized<T>() -> Result<(), UserAccessError> {
    if size_of::<T>() == 0 {
        return Err(UserAccessError::ZeroSizedType);
    }
    Ok(())
}

fn total_bytes<T>(len: usize) -> Result<usize, UserAccessError> {
    len.checked_mul(size_of::<T>())
        .ok_or(UserAccessError::AddressOverflow)
}

fn is_lower_canonical(addr: usize) -> bool {
    // Assumes 4-level paging (48-bit canonical addresses).
    (addr >> 47) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{println, test::kernel_test_case};

    #[kernel_test_case]
    fn rejects_null_with_len() {
        println!("[test] rejects_null_with_len");

        let ptr = VirtAddr::new(core::ptr::null::<u8>() as usize);
        assert_eq!(
            validate_user_range(ptr, 8),
            Err(UserAccessError::NullPointer)
        );
    }

    #[kernel_test_case]
    fn allows_zero_len_null() {
        println!("[test] allows_zero_len_null");

        let ptr = VirtAddr::new(0);
        assert_eq!(validate_user_range(ptr, 0), Ok(()));
    }

    #[kernel_test_case]
    fn detects_overflow() {
        println!("[test] detects_overflow");

        let ptr = VirtAddr::new(USER_SPACE_LIMIT - 4);
        assert_eq!(
            validate_user_range(ptr, 8),
            Err(UserAccessError::OutOfRange)
        );
    }

    #[kernel_test_case]
    fn misalignment_error() {
        println!("[test] misalignment_error");

        let ptr = VirtAddr::new(3);
        let result = with_user_slice::<u32, _, _>(ptr, 1, |_slice| ());
        assert!(matches!(
            result,
            Err(UserAccessError::Misaligned { alignment: 4 })
        ));
    }

    #[kernel_test_case]
    fn totalsize_overflow() {
        println!("[test] totalsize_overflow");

        let ptr = VirtAddr::new(0x1000);
        let result = with_user_slice::<u64, _, _>(ptr, usize::MAX / 2, |_slice| ());
        assert_eq!(result, Err(UserAccessError::AddressOverflow));
    }
}
