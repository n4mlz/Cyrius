use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use super::VfsError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Path {
    absolute: bool,
    components: Vec<PathComponent>,
}

impl Path {
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

    pub fn resolve(raw: &str, base: &Path) -> Result<Self, VfsError> {
        if raw.is_empty() {
            return Err(VfsError::InvalidPath);
        }

        let (absolute, mut components) = if raw.starts_with('/') {
            (true, Vec::new())
        } else {
            (base.absolute, base.components.clone())
        };

        components = normalize_components(components, raw, false)?;

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

    pub fn from_components(absolute: bool, components: Vec<PathComponent>) -> Self {
        Self {
            absolute,
            components,
        }
    }

    pub fn join(&self, other: &Path) -> Result<Self, VfsError> {
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

pub(crate) fn normalize_components(
    mut components: Vec<PathComponent>,
    raw: &str,
    strict_parent: bool,
) -> Result<Vec<PathComponent>, VfsError> {
    let path = raw.strip_prefix('/').unwrap_or(raw);
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            if components.is_empty() {
                if strict_parent {
                    return Err(VfsError::InvalidPath);
                }
            } else {
                components.pop();
            }
            continue;
        }
        if part.len() > 255 {
            return Err(VfsError::NameTooLong);
        }
        components.push(PathComponent::new(part));
    }
    Ok(components)
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.absolute {
            write!(f, "/")?;
        }
        let mut iter = self.components.iter().peekable();
        while let Some(comp) = iter.next() {
            write!(f, "{}", comp.as_str())?;
            if iter.peek().is_some() {
                write!(f, "/")?;
            }
        }
        Ok(())
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
