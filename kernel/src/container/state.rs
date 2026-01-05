use alloc::collections::BTreeMap;
use alloc::string::String;

use crate::process::ProcessId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerStatus {
    Created,
    Running,
    Stopped,
}

impl ContainerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Running => "running",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerState {
    pub oci_version: String,
    pub id: String,
    pub status: ContainerStatus,
    pub pid: Option<ProcessId>,
    pub bundle_path: String,
    pub annotations: BTreeMap<String, String>,
}
