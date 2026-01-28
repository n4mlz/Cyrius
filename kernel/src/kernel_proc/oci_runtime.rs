use alloc::format;
use alloc::string::{String, ToString};

use crate::container::runtime::{ContainerStartError, start_container_by_id};
use crate::container::{CONTAINER_TABLE, ContainerError};
use crate::fs::Path;
use crate::process::fs as proc_fs;
use crate::process::{PROCESS_TABLE, ProcessId};

#[derive(Debug)]
pub enum OciRuntimeError {
    Fs(crate::fs::VfsError),
    Container(ContainerError),
    Start(ContainerStartError),
    State(crate::fs::VfsError),
}

pub fn create_container(pid: ProcessId, id: &str, bundle: &str) -> Result<String, OciRuntimeError> {
    let bundle = resolve_abs_path(pid, bundle)?;
    CONTAINER_TABLE
        .create(id, bundle.as_str())
        .map_err(OciRuntimeError::Container)?;
    Ok(format!("container {id} created"))
}

pub fn start_container(id: &str) -> Result<ProcessId, OciRuntimeError> {
    start_container_by_id(id).map_err(OciRuntimeError::Start)
}

pub fn wait_for_exit(pid: ProcessId) {
    while PROCESS_TABLE
        .thread_count(pid)
        .map(|count| count > 0)
        .unwrap_or(false)
    {
        #[cfg(target_arch = "x86_64")]
        crate::arch::x86_64::halt();
        #[cfg(not(target_arch = "x86_64"))]
        core::hint::spin_loop();
    }
}

pub fn state_container(id: &str) -> Result<String, OciRuntimeError> {
    let container = CONTAINER_TABLE
        .get(id)
        .ok_or(OciRuntimeError::Container(ContainerError::NotFound))?;
    let state = container.state();
    let mut annotations = serde_json::Map::new();
    for (key, value) in state.annotations.iter() {
        annotations.insert(key.clone(), serde_json::Value::String(value.clone()));
    }
    let pid_value = match state.pid {
        Some(pid) => serde_json::Value::Number(serde_json::Number::from(pid)),
        None => serde_json::Value::Null,
    };
    let json = serde_json::json!({
        "ociVersion": state.oci_version,
        "id": state.id,
        "status": state.status.as_str(),
        "pid": pid_value,
        "bundle": state.bundle_path,
        "annotations": serde_json::Value::Object(annotations),
    });
    serde_json::to_string(&json).map_err(|_| OciRuntimeError::State(crate::fs::VfsError::Corrupted))
}

fn resolve_abs_path(pid: ProcessId, raw: &str) -> Result<String, OciRuntimeError> {
    let cwd = proc_fs::cwd(pid).map_err(OciRuntimeError::Fs)?;
    let abs = Path::resolve(raw, &cwd).map_err(OciRuntimeError::Fs)?;
    Ok(abs.to_string())
}
