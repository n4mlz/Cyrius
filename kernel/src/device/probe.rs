use crate::device::block::BlockDeviceProvider;
use crate::device::net::NetworkDeviceProvider;

pub fn probe_block_devices() -> usize {
    crate::device::virtio::block::VirtioBlockProvider.probe()
}

pub fn probe_network_devices() -> usize {
    crate::device::virtio::net::VirtioNetProvider.probe()
}
