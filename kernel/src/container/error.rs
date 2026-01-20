use crate::fs::VfsError;

#[derive(Debug)]
pub enum ContainerError {
    DuplicateId,
    InvalidId,
    NotFound,
    InvalidState,
    BundlePathNotAbsolute,
    MissingRoot,
    Vfs(VfsError),
    ConfigNotUtf8,
    ConfigParseFailed,
}

impl From<VfsError> for ContainerError {
    fn from(err: VfsError) -> Self {
        Self::Vfs(err)
    }
}
