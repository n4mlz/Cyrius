use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use super::VfsError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VfsPath {
    absolute: bool,
    components: Vec<PathComponent>,
}

impl VfsPath {
    pub fn parse(raw: &str) -> Result<Self, VfsError> {
        if raw.is_empty() {
            return Err(VfsError::InvalidPath);
        }

        let absolute = raw.starts_with('/');
        let mut components = Vec::new();

        for part in raw.split('/') {
            if part.is_empty() || part == "." {
                continue;
            }
            if part == ".." {
                return Err(VfsError::InvalidPath);
            }
            if part.len() > 255 {
                return Err(VfsError::NameTooLong);
            }
            components.push(PathComponent::new(part));
        }

        Ok(Self {
            absolute,
            components,
        })
    }

    pub fn is_absolute(&self) -> bool {
        self.absolute
    }

    pub fn components(&self) -> &[PathComponent] {
        &self.components
    }

    pub fn root() -> Self {
        Self {
            absolute: true,
            components: Vec::new(),
        }
    }

    pub fn join(&self, other: &VfsPath) -> Result<Self, VfsError> {
        if other.is_absolute() {
            return Ok(other.clone());
        }
        let mut components = self.components.clone();
        for comp in other.components.iter() {
            components.push(comp.clone());
        }
        Ok(Self {
            absolute: self.absolute,
            components,
        })
    }

    pub fn push(&mut self, component: PathComponent) {
        self.components.push(component);
    }

    pub fn parent(&self) -> Option<Self> {
        if self.components.is_empty() {
            return None;
        }
        let mut comps = self.components.clone();
        comps.pop();
        Some(Self {
            absolute: self.absolute,
            components: comps,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathComponent {
    raw: String,
}

impl PathComponent {
    pub fn new(raw: &str) -> Self {
        Self {
            raw: raw.to_string(),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }
}
