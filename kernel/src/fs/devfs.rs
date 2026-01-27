use alloc::sync::Arc;

use super::PathComponent;
use super::{CharDeviceNode, Node, VfsError};
use crate::device::tty;

pub fn global_tty_node() -> Arc<dyn Node> {
    CharDeviceNode::new(tty::global_tty())
}

pub fn install_default_nodes(root: &dyn Node) -> Result<(), VfsError> {
    let root_dir = root.as_dir().ok_or(VfsError::NotDirectory)?;

    let dev_dir = match root_dir.lookup(&PathComponent::new("dev")) {
        Ok(dir) => {
            let _dir_view = dir.as_dir().ok_or(VfsError::NotDirectory)?;
            dir
        }
        Err(VfsError::NotFound) => root_dir.create_dir("dev")?,
        Err(err) => return Err(err),
    };
    let dev_dir_view = dev_dir.as_dir().ok_or(VfsError::NotDirectory)?;

    let tty_node = global_tty_node();
    let _ = dev_dir_view.unlink("tty");
    dev_dir_view.link("tty", tty_node)?;

    let console_node = global_tty_node();
    let _ = dev_dir_view.unlink("console");
    dev_dir_view.link("console", console_node)?;

    Ok(())
}
