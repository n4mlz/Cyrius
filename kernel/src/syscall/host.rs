use alloc::string::{String, ToString};

use super::{SysError, SysResult, SyscallInvocation};
use crate::container::runtime::start_container_by_id;
use crate::container::{CONTAINER_TABLE, ContainerError};
use crate::mem::addr::VirtAddr;
use crate::mem::user::copy_from_user;

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostErrno {
    NotImplemented = 1,
    InvalidArgument = 2,
    NotFound = 3,
    BadAddress = 4,
}

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostSyscall {
    ContainerCreate = 1,
    ContainerStart = 2,
}

impl HostSyscall {
    pub fn from_raw(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::ContainerCreate),
            2 => Some(Self::ContainerStart),
            _ => None,
        }
    }
}

/// Host ABI dispatch table.
pub fn dispatch(invocation: &SyscallInvocation) -> SysResult {
    match HostSyscall::from_raw(invocation.number) {
        Some(HostSyscall::ContainerCreate) => handle_container_create(invocation),
        Some(HostSyscall::ContainerStart) => handle_container_start(invocation),
        None => Err(SysError::NotImplemented),
    }
}

pub fn encode_result(result: SysResult) -> u64 {
    match result {
        Ok(val) => val,
        Err(err) => encode_error(err),
    }
}

fn encode_error(err: SysError) -> u64 {
    match err {
        SysError::NotImplemented => HostErrno::NotImplemented as u64,
        SysError::InvalidArgument => HostErrno::InvalidArgument as u64,
        SysError::NotFound => HostErrno::NotFound as u64,
        SysError::BadAddress => HostErrno::BadAddress as u64,
        SysError::NotTty => HostErrno::InvalidArgument as u64,
    }
}

fn handle_container_create(invocation: &SyscallInvocation) -> SysResult {
    let id_ptr = invocation.arg(0).ok_or(SysError::InvalidArgument)?;
    let id_len = invocation.arg(1).ok_or(SysError::InvalidArgument)?;
    let bundle_ptr = invocation.arg(2).ok_or(SysError::InvalidArgument)?;
    let bundle_len = invocation.arg(3).ok_or(SysError::InvalidArgument)?;

    let id = read_str(id_ptr, id_len)?;
    let bundle = read_str(bundle_ptr, bundle_len)?;

    match CONTAINER_TABLE.create(id.as_str(), bundle.as_str()) {
        Ok(_) => Ok(0),
        Err(ContainerError::DuplicateId | ContainerError::InvalidId) => {
            Err(SysError::InvalidArgument)
        }
        Err(_) => Err(SysError::InvalidArgument),
    }
}

fn handle_container_start(invocation: &SyscallInvocation) -> SysResult {
    let id_ptr = invocation.arg(0).ok_or(SysError::InvalidArgument)?;
    let id_len = invocation.arg(1).ok_or(SysError::InvalidArgument)?;
    let id = read_str(id_ptr, id_len)?;

    start_container_by_id(id.as_str()).map_err(|_| SysError::InvalidArgument)
}

fn read_str(ptr: u64, len: u64) -> Result<String, SysError> {
    let len = usize::try_from(len).map_err(|_| SysError::InvalidArgument)?;
    if len == 0 {
        return Err(SysError::InvalidArgument);
    }
    let mut buf = alloc::vec![0u8; len];
    copy_from_user(&mut buf, VirtAddr::new(ptr as usize)).map_err(|_| SysError::InvalidArgument)?;
    let text = core::str::from_utf8(&buf).map_err(|_| SysError::InvalidArgument)?;
    Ok(text.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::Node;
    use crate::fs::force_replace_root;
    use crate::fs::memfs::MemDirectory;
    use crate::println;
    use crate::test::kernel_test_case;

    #[kernel_test_case]
    fn container_create_syscall_registers_container() {
        println!("[test] container_create_syscall_registers_container");

        let root = MemDirectory::new();
        force_replace_root(root.clone());
        CONTAINER_TABLE.clear_for_tests();

        let bundle_dir = root.create_dir("bundle").expect("create bundle dir");
        let _ = bundle_dir.create_dir("rootfs").expect("create rootfs dir");
        let config = bundle_dir
            .create_file("config.json")
            .expect("create config");
        let handle = config
            .open(crate::fs::OpenOptions::new(0))
            .expect("open config");
        handle
            .write(br#"{"ociVersion":"1.0.2","root":{"path":"rootfs"}}"#)
            .expect("write config");

        let id = "syscall-demo";
        let bundle = "/bundle";
        let invocation = SyscallInvocation::new(
            HostSyscall::ContainerCreate as u64,
            [
                id.as_ptr() as u64,
                id.len() as u64,
                bundle.as_ptr() as u64,
                bundle.len() as u64,
                0,
                0,
            ],
        );

        let result = dispatch(&invocation);
        assert!(result.is_ok(), "syscall failed: {:?}", result);
        assert!(CONTAINER_TABLE.get(id).is_some());
    }
}
