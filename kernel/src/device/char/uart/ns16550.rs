use core::marker::PhantomData;

use crate::cast;
use crate::device::bus::reg::{RegBus, RegSizeBound};
use crate::device::char::CharDevice;
use crate::device::char::uart::Uart;
use crate::device::{Device, DeviceType};
use crate::util::stream::{ReadOps, StreamError, WriteOps};

const RBR: usize = 0;
const THR: usize = 0;
const IER: usize = 1;
const LCR: usize = 3;
const MCR: usize = 4;
const LSR: usize = 5;
const FCR: usize = 2;

/// Minimal 16550-compatible UART driver layered on top of a register bus.
///
/// # Implicit contract
///
/// The supplied [`RegBus`] implementation must guarantee exclusive access to the UART
/// registers and deliver deterministic ordering for byte-level reads/writes. Hardware
/// faults are surfaced via [`StreamError::Transport`] and are expected to be handled by
/// higher layers.
pub struct Ns16550<RegSize: RegSizeBound, R: RegBus<RegSize>> {
    pub regs: R,
    pub name: &'static str,
    _marker: PhantomData<fn() -> RegSize>,
}

impl<RegSize: RegSizeBound, R: RegBus<RegSize>> Ns16550<RegSize, R> {
    pub const fn new(regs: R, name: &'static str) -> Self {
        Self {
            regs,
            name,
            _marker: PhantomData,
        }
    }

    fn lsr(&self) -> Result<RegSize, StreamError<R::Error>> {
        self.regs.read(LSR).map_err(StreamError::transport)
    }

    fn rbr(&self) -> Result<RegSize, StreamError<R::Error>> {
        self.regs.read(RBR).map_err(StreamError::transport)
    }

    fn out(&self, offset: usize, value: RegSize) -> Result<(), StreamError<R::Error>> {
        self.regs
            .write(offset, value)
            .map_err(StreamError::transport)
    }
}

impl<RegSize: RegSizeBound, R: RegBus<RegSize>> Device for Ns16550<RegSize, R> {
    fn name(&self) -> &str {
        self.name
    }
    fn device_type(&self) -> DeviceType {
        DeviceType::Char
    }
}

impl<RegSize: RegSizeBound, R: RegBus<RegSize>> ReadOps for Ns16550<RegSize, R> {
    type Error = StreamError<R::Error>;

    fn read(&self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let mut i = 0;
        while i < buf.len() {
            if self.rx_ready()? {
                buf[i] = cast!(self.rbr()?);
                i += 1;
            } else {
                break;
            }
        }
        Ok(i)
    }
}

impl<RegSize: RegSizeBound, R: RegBus<RegSize>> WriteOps for Ns16550<RegSize, R> {
    type Error = StreamError<R::Error>;

    fn write(&self, buf: &[u8]) -> Result<usize, Self::Error> {
        let mut i = 0;
        while i < buf.len() {
            loop {
                if self.tx_ready()? {
                    break;
                }
                core::hint::spin_loop();
            }
            self.out(THR, cast!(buf[i]))?;
            i += 1;
        }
        Ok(i)
    }
}

impl<RegSize: RegSizeBound, R: RegBus<RegSize>> CharDevice for Ns16550<RegSize, R> {
    type Error = StreamError<R::Error>;
}

impl<RegSize: RegSizeBound, R: RegBus<RegSize>> Uart for Ns16550<RegSize, R> {
    fn init(&self) -> Result<(), <Self as CharDevice>::Error> {
        self.out(IER, cast!(0x00))?;
        self.out(LCR, cast!(0x80))?; // DLAB=1
        self.out(0, cast!(0x03))?; // DLL
        self.out(1, cast!(0x00))?; // DLM
        self.out(LCR, cast!(0x03))?; // 8N1
        self.out(FCR, cast!(0xC7))?; // FIFO enable/clear
        self.out(MCR, cast!(0x0B))?; // DTR|RTS|OUT2
        Ok(())
    }

    fn tx_ready(&self) -> Result<bool, <Self as CharDevice>::Error> {
        let status = self.lsr()?;
        Ok((status & cast!(0x20)) != cast!(0))
    }

    fn rx_ready(&self) -> Result<bool, <Self as CharDevice>::Error> {
        let status = self.lsr()?;
        Ok((status & cast!(0x01)) != cast!(0))
    }
}
