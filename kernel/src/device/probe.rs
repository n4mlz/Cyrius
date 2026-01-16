use crate::device::block::BlockDeviceProvider;

pub fn probe_block_devices() -> usize {
    crate::device::virtio::block::VirtioBlockProvider.probe()
}
