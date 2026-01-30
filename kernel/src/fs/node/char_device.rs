use alloc::sync::Arc;

use crate::device::Device;
use crate::device::char::CharDevice;
use crate::util::stream::{ControlError, ControlOps, ControlRequest};

use super::{Node, NodeKind, NodeStat, OpenOptions};
use crate::fs::{File, VfsError};

/// Generic character device node that delegates to a device driver.
pub struct CharDeviceNode<D> {
    device: Arc<D>,
}

impl<D> CharDeviceNode<D> {
    pub fn new(device: Arc<D>) -> Arc<Self> {
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
            size: 0,
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

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}
