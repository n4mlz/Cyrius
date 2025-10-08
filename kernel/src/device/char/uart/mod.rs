pub mod ns16550;

use crate::device::char::CharDevice;

pub trait Uart: CharDevice {
    fn init(&self) -> Result<(), <Self as CharDevice>::Error>;
    fn tx_ready(&self) -> Result<bool, <Self as CharDevice>::Error>;
    fn rx_ready(&self) -> Result<bool, <Self as CharDevice>::Error>;
}
