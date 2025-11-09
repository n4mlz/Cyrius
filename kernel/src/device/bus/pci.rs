use core::convert::TryInto;

use x86_64::instructions::port::Port;

use crate::mem::addr::PhysAddr;

/// Simple PCI configuration space accessor for legacy 0xCF8/0xCFC bridge.
#[derive(Clone, Copy, Debug)]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciAddress {
    fn config_address(&self, offset: u8) -> u32 {
        let offset = (offset & 0xFC) as u32;
        (1 << 31)
            | ((self.bus as u32) << 16)
            | ((self.device as u32) << 11)
            | ((self.function as u32) << 8)
            | offset
    }

    pub fn read_u32(&self, offset: u8) -> u32 {
        unsafe {
            let mut addr = Port::<u32>::new(0xCF8);
            addr.write(self.config_address(offset));
            let mut data = Port::<u32>::new(0xCFC);
            data.read()
        }
    }

    pub fn read_u16(&self, offset: u8) -> u16 {
        let value = self.read_u32(offset & !0x2);
        let shift = (offset & 0x2) * 8;
        ((value >> shift) & 0xFFFF) as u16
    }

    pub fn read_u8(&self, offset: u8) -> u8 {
        let value = self.read_u32(offset & !0x3);
        let shift = (offset & 0x3) * 8;
        ((value >> shift) & 0xFF) as u8
    }

    pub fn write_u16(&self, offset: u8, value: u16) {
        let aligned = offset & !0x2;
        let current = self.read_u32(aligned);
        let shift = (offset & 0x2) * 8;
        let mask = !(0xFFFFu32 << shift);
        let new_value = (current & mask) | ((value as u32) << shift);
        unsafe {
            let mut addr = Port::<u32>::new(0xCF8);
            addr.write(self.config_address(aligned));
            let mut data = Port::<u32>::new(0xCFC);
            data.write(new_value);
        }
    }

    pub fn enable_bus_master_and_mem(&self) {
        let mut command = self.read_u16(0x04);
        command |= 0x0006; // enable memory space + bus mastering
        self.write_u16(0x04, command);
    }

    pub fn bar_address(&self, index: u8) -> Option<PhysAddr> {
        if index >= 6 {
            return None;
        }

        let offset = 0x10u8.checked_add(index.saturating_mul(4))?;
        let raw = self.read_u32(offset);
        if raw == 0 || raw == u32::MAX {
            return None;
        }
        if raw & 1 != 0 {
            return None; // I/O BAR not supported yet
        }

        let ty = (raw >> 1) & 0x3;
        let base_low = (raw & !0xFu32) as u64;

        let base = if ty == 0x2 {
            // 64-bit BAR spans the next slot as well.
            let next_offset = 0x10u8.checked_add(index.saturating_add(1).saturating_mul(4))?;
            let high = self.read_u32(next_offset) as u64;
            (high << 32) | base_low
        } else {
            base_low
        };

        if base == 0 {
            return None;
        }

        let addr: usize = base.try_into().ok()?;
        Some(PhysAddr::new(addr))
    }
}

pub fn find_device(vendor: u16, device: u16) -> Option<PciAddress> {
    for bus in 0u8..=0 {
        for dev in 0u8..32 {
            for func in 0u8..8 {
                let address = PciAddress {
                    bus,
                    device: dev,
                    function: func,
                };
                let ident = address.read_u32(0x00);
                if ident == 0xFFFF_FFFF {
                    if func == 0 {
                        break;
                    }
                    continue;
                }
                let vendor_id = (ident & 0xFFFF) as u16;
                let device_id = ((ident >> 16) & 0xFFFF) as u16;
                if vendor_id == vendor && device_id == device {
                    return Some(address);
                }
            }
        }
    }
    None
}
