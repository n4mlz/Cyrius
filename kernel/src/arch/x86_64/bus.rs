use crate::device::bus::reg::RegBus;

pub struct Pio {
    base: u16,
}

impl Pio {
    pub const fn new(base: u16) -> Self {
        Self { base }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PioError;

impl core::fmt::Display for PioError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PIO error")
    }
}

impl RegBus<u8> for Pio {
    type Error = PioError;

    fn read(&self, offset: usize) -> Result<u8, Self::Error> {
        let port = self.base + offset as u16;
        let value: u8;
        unsafe {
            core::arch::asm!("in al, dx", in("dx") port, out("al") value);
        }
        Ok(value)
    }

    fn write(&self, offset: usize, value: u8) -> Result<(), Self::Error> {
        let port = self.base + offset as u16;
        unsafe {
            core::arch::asm!("out dx, al", in("dx") port, in("al") value);
        }
        Ok(())
    }
}
