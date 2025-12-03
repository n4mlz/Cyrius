pub mod block;
pub mod bus;
pub mod char;
pub mod virtio;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceType {
    Block,
    Char,
    Network,
}

pub trait Device {
    fn name(&self) -> &str;
    fn device_type(&self) -> DeviceType;
}
