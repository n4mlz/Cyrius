use alloc::format;
use alloc::string::{String, ToString};

use crate::container::{CONTAINER_TABLE, ContainerError};
use crate::fs::VfsPath;
use crate::process::ProcessId;
use crate::process::fs as proc_fs;

#[derive(Debug)]
pub enum OciRuntimeError {
    Fs(crate::fs::VfsError),
    Container(ContainerError),
}

pub fn create_container(pid: ProcessId, id: &str, bundle: &str) -> Result<String, OciRuntimeError> {
    let bundle = resolve_abs_path(pid, bundle)?;
    CONTAINER_TABLE
        .create(id, bundle.as_str())
        .map_err(OciRuntimeError::Container)?;
    Ok(format!("container {id} created"))
}

fn resolve_abs_path(pid: ProcessId, raw: &str) -> Result<String, OciRuntimeError> {
    let cwd = proc_fs::cwd(pid).map_err(OciRuntimeError::Fs)?;
    let abs = VfsPath::resolve(raw, &cwd).map_err(OciRuntimeError::Fs)?;
    Ok(abs.to_string())
}
