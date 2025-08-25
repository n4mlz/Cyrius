pub mod uart;

use crate::device::Device;

pub trait CharDevice: Device {
    fn read(&self, buffer: &mut [u8]) -> usize;
    fn write(&self, buffer: &[u8]) -> usize;
}
