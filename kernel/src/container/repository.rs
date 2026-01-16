use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;

use crate::util::spinlock::SpinLock;

use super::{Container, ContainerError};

pub struct ContainerRepository {
    inner: SpinLock<BTreeMap<String, Arc<Container>>>,
}

impl ContainerRepository {
    pub const fn new() -> Self {
        Self {
            inner: SpinLock::new(BTreeMap::new()),
        }
    }

    pub fn insert(&self, id: &str, container: Arc<Container>) -> Result<Arc<Container>, ContainerError> {
        let mut guard = self.inner.lock();
        if guard.contains_key(id) {
            return Err(ContainerError::DuplicateId);
        }
        guard.insert(id.to_string(), container.clone());
        Ok(container)
    }

    pub fn get(&self, id: &str) -> Option<Arc<Container>> {
        let guard = self.inner.lock();
        guard.get(id).cloned()
    }

    #[cfg(test)]
    pub fn clear_for_tests(&self) {
        let mut guard = self.inner.lock();
        guard.clear();
    }
}

impl Default for ContainerRepository {
    fn default() -> Self {
        Self::new()
    }
}
