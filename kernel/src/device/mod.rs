pub mod block;
pub mod bus;
pub mod char;
pub mod virtio;

pub enum DeviceType {
    Block,
    Char,
    Network,
}

pub trait Device {
    fn name(&self) -> &str;
    fn device_type(&self) -> DeviceType;
}
