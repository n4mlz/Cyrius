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
    let (user_image, entry) = image.into_parts();

    SCHEDULER
        .spawn_user_thread(pid, spec.name, entry, 0, Some(user_image))
        .map_err(RunError::Spawn)?;

    Ok(pid)
}
