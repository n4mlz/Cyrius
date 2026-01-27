use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::process::ProcessId;
use crate::util::spinlock::SpinLock;
use oci_spec::runtime::Spec;

pub mod context;
mod error;
mod repository;
pub mod runtime;
mod spec;
pub mod state;
mod table;

pub use context::ContainerContext;
pub use error::ContainerError;
pub use repository::ContainerRepository;
pub use spec::{SpecLoader, SpecMetadata};
pub use state::{ContainerState, ContainerStatus};
pub use table::{CONTAINER_TABLE, ContainerTable};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerVfsBacking {
    Ramfs,
}

pub const CONTAINER_VFS_BACKING: ContainerVfsBacking = ContainerVfsBacking::Ramfs;

struct ContainerMutable {
    state: ContainerState,
    context: ContainerContext,
    processes: Vec<ProcessId>,
}

pub struct Container {
    mutable: SpinLock<ContainerMutable>,
    spec: Arc<Spec>,
}

impl Container {
    pub fn new(state: ContainerState, spec: Spec, context: ContainerContext) -> Self {
        Self {
            mutable: SpinLock::new(ContainerMutable {
                state,
                context,
                processes: Vec::new(),
            }),
            spec: Arc::new(spec),
        }
    }

    pub fn id(&self) -> String {
        self.mutable.lock().state.id.clone()
    }

    pub fn state(&self) -> ContainerState {
        self.mutable.lock().state.clone()
    }

    pub fn spec(&self) -> &Spec {
        self.spec.as_ref()
    }

    pub fn context(&self) -> ContainerContext {
        self.mutable.lock().context.clone()
    }

    pub fn vfs(&self) -> Arc<crate::fs::Vfs> {
        self.mutable.lock().context.vfs()
    }

    pub fn rootfs(&self) -> Arc<dyn crate::fs::Node> {
        self.mutable.lock().context.rootfs()
    }

    pub fn mark_running(&self, pid: ProcessId) -> Result<(), ContainerError> {
        let mut guard = self.mutable.lock();
        if guard.state.status != ContainerStatus::Created {
            return Err(ContainerError::InvalidState);
        }
        guard.state.status = ContainerStatus::Running;
        guard.state.pid = Some(pid);
        if !guard.processes.contains(&pid) {
            guard.processes.push(pid);
        }
        Ok(())
    }

    pub fn record_process(&self, pid: ProcessId) {
        let mut guard = self.mutable.lock();
        if !guard.processes.contains(&pid) {
            guard.processes.push(pid);
        }
    }
}
