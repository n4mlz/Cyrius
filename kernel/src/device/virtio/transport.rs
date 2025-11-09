use core::fmt;

use bitflags::bitflags;

use crate::device::virtio::queue::QueueConfig;

bitflags! {
    pub struct DeviceStatus: u8 {
        const ACKNOWLEDGE = 1;
        const DRIVER = 2;
        const DRIVER_OK = 4;
        const FEATURES_OK = 8;
        const NEEDS_RESET = 64;
        const FAILED = 128;
    }
}

impl DeviceStatus {
    pub fn with(self, other: DeviceStatus) -> DeviceStatus {
        self.union(other)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    CapabilityMissing(&'static str),
    QueueUnavailable,
    InvalidQueueSize,
    NotifyUnavailable,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapabilityMissing(name) => write!(f, "missing VirtIO capability: {name}"),
            Self::QueueUnavailable => write!(f, "requested queue index is unavailable"),
            Self::InvalidQueueSize => write!(f, "queue size rejected by the device"),
            Self::NotifyUnavailable => write!(f, "queue notify region unavailable"),
        }
    }
}

pub trait QueueNotifier {
    fn notify_queue(&self, queue_index: u16) -> Result<(), TransportError>;
}

pub trait Transport: QueueNotifier {
    fn device_id(&self) -> u16;
    fn read_device_features(&self, select: u32) -> u32;
    fn write_driver_features(&self, select: u32, value: u32);
    fn num_queues(&self) -> u16;
    fn status(&self) -> DeviceStatus;
    fn set_status(&self, status: DeviceStatus);
    fn config_generation(&self) -> u8;
    fn select_queue(&self, queue_index: u16) -> Result<(), TransportError>;
    fn queue_size(&self) -> Result<u16, TransportError>;
    fn set_queue_size(&self, size: u16) -> Result<(), TransportError>;
    fn program_queue(&self, cfg: &QueueConfig) -> Result<(), TransportError>;
    fn enable_queue(&self, enabled: bool) -> Result<(), TransportError>;
}
