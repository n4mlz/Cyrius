use alloc::sync::Arc;

use crate::device::Device;
use crate::device::char::CharDevice;
use crate::device::tty;
use crate::util::stream::{ControlError, ControlOps, ControlRequest};

use super::File;
use super::PathComponent;
use super::{Node, NodeKind, NodeStat, OpenOptions, VfsError};

struct CharDeviceNode<D> {
    device: Arc<D>,
}

impl<D> CharDeviceNode<D> {
    fn new(device: Arc<D>) -> Arc<Self> {
        Arc::new(Self { device })
    }
}

impl<D> Node for CharDeviceNode<D>
where
    D: Device + CharDevice + ControlOps + Send + Sync + 'static,
{
    fn kind(&self) -> NodeKind {
        NodeKind::CharDevice
    }

    fn stat(&self) -> Result<NodeStat, VfsError> {
        Ok(NodeStat {
            kind: NodeKind::CharDevice,
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
        })
    }

    fn open(self: Arc<Self>, _options: OpenOptions) -> Result<Arc<dyn File>, VfsError> {
        Ok(Arc::new(DeviceFile::new(self.device.clone())))
    }
}

struct DeviceFile<D> {
    device: Arc<D>,
}

impl<D> DeviceFile<D> {
    fn new(device: Arc<D>) -> Self {
        Self { device }
    }
}

impl<D> File for DeviceFile<D>
where
    D: Device + CharDevice + ControlOps + Send + Sync + 'static,
{
    fn read(&self, buf: &mut [u8]) -> Result<usize, VfsError> {
        self.device
            .read(buf)
            .map_err(|_| VfsError::UnderlyingDevice)
    }

    fn write(&self, data: &[u8]) -> Result<usize, VfsError> {
        self.device
            .write(data)
            .map_err(|_| VfsError::UnderlyingDevice)
    }

    fn ioctl(&self, request: &ControlRequest<'_>) -> Result<u64, ControlError> {
        self.device.control(request)
    }
}

pub fn global_tty_node() -> Arc<dyn Node> {
    CharDeviceNode::new(tty::global_tty())
}

pub fn install_default_nodes(root: &dyn Node) -> Result<(), VfsError> {
    if root.kind() != NodeKind::Directory {
        return Err(VfsError::NotDirectory);
    }

    let dev_dir = match root.lookup(&PathComponent::new("dev")) {
        Ok(dir) if dir.kind() == NodeKind::Directory => dir,
        Ok(_) => return Err(VfsError::NotDirectory),
        Err(VfsError::NotFound) => root.create_dir("dev")?,
        Err(err) => return Err(err),
    };

    let tty_node = global_tty_node();
    let _ = dev_dir.unlink("tty");
    dev_dir.link("tty", tty_node)?;

    let console_node = global_tty_node();
    let _ = dev_dir.unlink("console");
    dev_dir.link("console", console_node)?;

    Ok(())
}
