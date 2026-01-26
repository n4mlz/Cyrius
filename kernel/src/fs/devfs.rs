use alloc::sync::Arc;

use crate::device::Device;
use crate::device::char::CharDevice;
use crate::device::tty;
use crate::util::stream::{ControlError, ControlOps, ControlRequest};

use super::Directory;
use super::{DeviceNode, FileType, Metadata, NodeRef, PathComponent, VfsError};

struct CharDeviceNode<D> {
    device: Arc<D>,
}

impl<D> CharDeviceNode<D> {
    fn new(device: Arc<D>) -> Arc<Self> {
        Arc::new(Self { device })
    }
}

impl<D> DeviceNode for CharDeviceNode<D>
where
    D: Device + CharDevice + ControlOps + Send + Sync + 'static,
{
    fn metadata(&self) -> Result<Metadata, VfsError> {
        Ok(Metadata {
            file_type: FileType::CharDevice,
            size: 0,
        })
    }

    fn read_at(&self, _offset: usize, buf: &mut [u8]) -> Result<usize, VfsError> {
        self.device
            .read(buf)
            .map_err(|_| VfsError::UnderlyingDevice)
    }

    fn write_at(&self, _offset: usize, data: &[u8]) -> Result<usize, VfsError> {
        self.device
            .write(data)
            .map_err(|_| VfsError::UnderlyingDevice)
    }

    fn control(&self, request: &ControlRequest<'_>) -> Result<u64, ControlError> {
        self.device.control(request)
    }
}

pub fn global_tty_node() -> Arc<dyn DeviceNode> {
    CharDeviceNode::new(tty::global_tty())
}

pub fn install_default_nodes(root: &dyn Directory) -> Result<(), VfsError> {
    let dev_dir = match root.lookup(&PathComponent::new("dev")) {
        Ok(NodeRef::Directory(dir)) => dir,
        Ok(_) => return Err(VfsError::NotDirectory),
        Err(VfsError::NotFound) => root.create_dir("dev")?,
        Err(err) => return Err(err),
    };

    let tty_node = global_tty_node();
    let _ = dev_dir.remove("tty");
    dev_dir.link("tty", NodeRef::Device(tty_node))?;

    let console_node = global_tty_node();
    let _ = dev_dir.remove("console");
    dev_dir.link("console", NodeRef::Device(console_node))?;

    Ok(())
}
