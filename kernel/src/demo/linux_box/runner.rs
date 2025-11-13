use core::fmt;

use crate::demo::linux_box::catalog::{LINUX_DEMOS, LinuxDemoSpec};
use crate::demo::linux_box::loader;
use crate::process::{PROCESS_TABLE, ProcessError, ProcessId};
use crate::syscall::{AbiFlavor, SyscallPolicy};
use crate::thread::{SCHEDULER, SpawnError};

#[derive(Debug)]
pub enum RunError {
    UnknownDemo,
    Process(ProcessError),
    AddressSpaceMissing,
    Loader(loader::LoaderError),
    Spawn(SpawnError),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownDemo => f.write_str("requested demo is not registered"),
            Self::Process(err) => write!(f, "failed to create process: {err:?}"),
            Self::AddressSpaceMissing => f.write_str("process missing address space"),
            Self::Loader(err) => write!(f, "failed to load demo image: {err}"),
            Self::Spawn(err) => write!(f, "failed to spawn demo thread: {err:?}"),
        }
    }
}

pub fn demos() -> &'static [LinuxDemoSpec] {
    LINUX_DEMOS
}

pub fn run_demo(name: &str, policy_override: Option<SyscallPolicy>) -> Result<ProcessId, RunError> {
    let spec = LINUX_DEMOS
        .iter()
        .find(|demo| demo.name == name)
        .ok_or(RunError::UnknownDemo)?;

    let policy = policy_override.unwrap_or(spec.default_policy);
    let pid = PROCESS_TABLE
        .create_user_process_with(spec.name, AbiFlavor::Linux, policy)
        .map_err(RunError::Process)?;

    let space = PROCESS_TABLE
        .address_space(pid)
        .ok_or(RunError::AddressSpaceMissing)?;

    let image = loader::load(pid, &space, spec.payload).map_err(RunError::Loader)?;
    let entry = image.entry();
    let user_image = image.into_user_image();

    SCHEDULER
        .spawn_user_thread(pid, spec.name, entry, 0, Some(user_image))
        .map_err(RunError::Spawn)?;

    Ok(pid)
}
