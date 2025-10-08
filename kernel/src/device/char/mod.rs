pub mod uart;

use crate::device::Device;
use crate::util::stream::{ReadOps, WriteOps};

pub trait CharDevice:
    Device
    + ReadOps<Error = <Self as CharDevice>::Error>
    + WriteOps<Error = <Self as CharDevice>::Error>
{
    type Error: core::fmt::Debug;
}
