use core::fmt::{Debug, Display};

use num_traits::{NumCast, PrimInt, Unsigned};

pub trait RegSizeBound = PrimInt + Unsigned + NumCast;

pub trait RegBus<RegSize: RegSizeBound> {
    type Error: Display + Debug;

    fn read(&self, offset: usize) -> Result<RegSize, Self::Error>;
    fn write(&self, offset: usize, value: RegSize) -> Result<(), Self::Error>;
}
