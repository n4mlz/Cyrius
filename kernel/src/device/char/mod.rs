pub mod uart;

use crate::{device::Device, util::stream::StreamOps};

pub trait CharDevice: Device + StreamOps {}
