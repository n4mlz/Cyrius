use alloc::sync::Arc;

use crate::device::Device;
use crate::util::spinlock::SpinLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    Up,
    Down,
    Unknown,
}

/// Common contract for Ethernet-like network devices.
///
/// Drivers expose synchronous transmit/receive primitives so the higher-level
/// network stack can remain transport-agnostic during early bring-up.
pub trait NetworkDevice: Device {
    type Error: core::fmt::Debug;

    /// Returns the hardware MAC address (zeroed if unavailable).
    fn mac_address(&self) -> [u8; 6];

    /// Maximum payload size supported by the interface (MTU).
    fn mtu(&self) -> usize;

    /// Current link state as reported by the device.
    fn link_state(&self) -> LinkState {
        LinkState::Unknown
    }

    /// Transmit a single Ethernet frame.
    fn transmit_frame(&mut self, frame: &[u8]) -> Result<(), Self::Error>;

    /// Receive a single Ethernet frame into `buffer`.
    ///
    /// Returns `Ok(None)` if no frame is available.
    fn receive_frame(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, Self::Error>;
}

pub trait NetworkDeviceProvider {
    type Device: NetworkDevice + Device;

    fn probe(&self) -> usize;
    fn with_devices<R>(&self, f: impl FnOnce(&[Arc<SpinLock<Self::Device>>]) -> R) -> R;
}

#[derive(Clone)]
pub struct SharedNetworkDevice<T> {
    inner: Arc<SpinLock<T>>,
    name: Arc<str>,
    device_type: crate::device::DeviceType,
}

impl<T> SharedNetworkDevice<T> {
    pub fn from_arc(inner: Arc<SpinLock<T>>) -> Self
    where
        T: Device,
    {
        let guard = inner.lock();
        let name: Arc<str> = Arc::from(guard.name());
        let device_type = guard.device_type();
        drop(guard);
        Self {
            inner,
            name,
            device_type,
        }
    }

    pub fn inner(&self) -> Arc<SpinLock<T>> {
        self.inner.clone()
    }

    pub fn label(&self) -> &str {
        &self.name
    }
}

impl<T: Device> Device for SharedNetworkDevice<T> {
    fn name(&self) -> &str {
        &self.name
    }

    fn device_type(&self) -> crate::device::DeviceType {
        self.device_type
    }
}

impl<T: NetworkDevice> NetworkDevice for SharedNetworkDevice<T> {
    type Error = T::Error;

    fn mac_address(&self) -> [u8; 6] {
        self.inner.lock().mac_address()
    }

    fn mtu(&self) -> usize {
        self.inner.lock().mtu()
    }

    fn link_state(&self) -> LinkState {
        self.inner.lock().link_state()
    }

    fn transmit_frame(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        self.inner.lock().transmit_frame(frame)
    }

    fn receive_frame(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        self.inner.lock().receive_frame(buffer)
    }
}
