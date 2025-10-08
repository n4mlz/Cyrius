use core::marker::PhantomData;

use crate::cast;
use crate::device::bus::reg::{RegBus, RegSizeBound};
use crate::device::char::CharDevice;
use crate::device::char::uart::Uart;
use crate::device::{Device, DeviceType};
use crate::util::stream::{StreamError, StreamOps};

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
/// The supplied [`RegBus`] implementation is expected to be infallible for the mapped
/// registers. The driver currently unwraps low-level I/O operations and will panic if
/// the bus returns an error. Consumers should either provide an infallible bus or wrap
/// this type in a safer abstraction that converts hardware faults into recoverable
/// errors.
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

    fn lsr(&self) -> RegSize {
        self.regs.read(LSR).unwrap()
    }

    fn rbr(&self) -> RegSize {
        self.regs.read(RBR).unwrap()
    }

    fn out(&self, offset: usize, value: RegSize) {
        self.regs.write(offset, value).unwrap()
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

impl<RegSize: RegSizeBound, R: RegBus<RegSize>> StreamOps for Ns16550<RegSize, R> {
    fn read(&self, buf: &mut [u8]) -> Result<usize, StreamError> {
        let mut i = 0;
        while i < buf.len() {
            if self.rx_ready() {
                buf[i] = cast!(self.rbr());
                i += 1;
            } else {
                break;
            }
        }
        Ok(i)
    }
    fn write(&self, buf: &[u8]) -> Result<usize, StreamError> {
        let mut i = 0;
        while i < buf.len() {
            while !self.tx_ready() {
                core::hint::spin_loop();
            }
            self.out(THR, cast!(buf[i]));
            i += 1;
        }
        Ok(i)
    }
}

impl<RegSize: RegSizeBound, R: RegBus<RegSize>> CharDevice for Ns16550<RegSize, R> {}

impl<RegSize: RegSizeBound, R: RegBus<RegSize>> Uart for Ns16550<RegSize, R> {
    type Error = ();

    fn init(&self) {
        self.out(IER, cast!(0x00));
        self.out(LCR, cast!(0x80)); // DLAB=1
        self.out(0, cast!(0x03)); // DLL
        self.out(1, cast!(0x00)); // DLM
        self.out(LCR, cast!(0x03)); // 8N1
        self.out(FCR, cast!(0xC7)); // FIFO enable/clear
        self.out(MCR, cast!(0x0B)); // DTR|RTS|OUT2
    }

    fn tx_ready(&self) -> bool {
        (self.lsr() & cast!(0x20)) != cast!(0)
    }

    fn rx_ready(&self) -> bool {
        (self.lsr() & cast!(0x01)) != cast!(0)
    }
}
