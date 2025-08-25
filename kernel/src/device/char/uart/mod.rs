pub mod ns16550;

use crate::device::char::CharDevice;

pub trait Uart: CharDevice {
    type Error;

    fn init(&self);
    fn tx_ready(&self) -> bool;
    fn rx_ready(&self) -> bool;
    fn read(&self) -> Result<u8, Self::Error>;
    fn write(&self, c: u8) -> Result<(), Self::Error>;
}
