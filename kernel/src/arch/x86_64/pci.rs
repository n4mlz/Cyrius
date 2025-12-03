use core::convert::TryFrom;

use crate::mem::addr::PhysAddr;
use x86_64::instructions::port::Port;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PciAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl PciAddress {
    pub const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }
}

fn address_value(addr: PciAddress, offset: u16) -> u32 {
    let aligned = offset & 0xFFFC;
    (1 << 31)
        | ((addr.bus as u32) << 16)
        | ((addr.device as u32) << 11)
        | ((addr.function as u32) << 8)
        | aligned as u32
}

fn read_u32(addr: PciAddress, offset: u16) -> u32 {
    unsafe {
        let mut address_port: Port<u32> = Port::new(0xCF8);
        address_port.write(address_value(addr, offset));
        let mut data_port: Port<u32> = Port::new(0xCFC);
        data_port.read()
    }
}

fn write_u32(addr: PciAddress, offset: u16, value: u32) {
    unsafe {
        let mut address_port: Port<u32> = Port::new(0xCF8);
        address_port.write(address_value(addr, offset));
        let mut data_port: Port<u32> = Port::new(0xCFC);
        data_port.write(value);
    }
}

fn read_u16(addr: PciAddress, offset: u16) -> u16 {
    let shift = (offset & 0x2) * 8;
    ((read_u32(addr, offset) >> shift) & 0xFFFF) as u16
}

fn write_u16(addr: PciAddress, offset: u16, value: u16) {
    let shift = (offset & 0x2) * 8;
    let mask = !(0xFFFFu32 << shift);
    let mut current = read_u32(addr, offset);
    current = (current & mask) | ((value as u32) << shift);
    write_u32(addr, offset, current);
}

pub fn read_u8(addr: PciAddress, offset: u16) -> u8 {
    let shift = (offset & 0x3) * 8;
    ((read_u32(addr, offset) >> shift) & 0xFF) as u8
}

pub fn write_u8(addr: PciAddress, offset: u16, value: u8) {
    let shift = (offset & 0x3) * 8;
    let mask = !(0xFFu32 << shift);
    let mut current = read_u32(addr, offset);
    current = (current & mask) | ((value as u32) << shift);
    write_u32(addr, offset, current);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarAddress {
    Memory { base: PhysAddr },
    Io { port: u16 },
}

pub fn read_bar(addr: PciAddress, bar_index: u8) -> Option<BarAddress> {
    let offset = 0x10 + (bar_index as u16) * 4;
    let value = read_u32(addr, offset);
    if value == 0 {
        return None;
    }

    if value & 0x1 == 1 {
        let port = (value & 0xFFFC) as u16;
        return Some(BarAddress::Io { port });
    }

    let ty = (value >> 1) & 0x3;
    let mut base = (value & 0xFFFF_FFF0) as u64;
    if ty == 0x2 {
        let upper = read_u32(addr, offset + 4);
        base |= (upper as u64) << 32;
    }

    let base = usize::try_from(base).expect("BAR base exceeds usize");
    Some(BarAddress::Memory {
        base: PhysAddr::new(base),
    })
}

pub fn enable_bus_mastering(addr: PciAddress) {
    const COMMAND_OFFSET: u16 = 0x04;
    const BUS_MASTER: u16 = 1 << 2;
    const MMIO: u16 = 1 << 1;
    let mut command = read_u16(addr, COMMAND_OFFSET);
    command |= BUS_MASTER | MMIO;
    write_u16(addr, COMMAND_OFFSET, command);
}

pub fn enumerate(mut f: impl FnMut(PciAddress)) {
    for bus in 0..=255 {
        for device in 0..32 {
            for function in 0..8 {
                let addr = PciAddress::new(bus as u8, device as u8, function as u8);
                let vendor = read_u16(addr, 0x00);
                if vendor == 0xFFFF {
                    if function == 0 {
                        break;
                    }
                    continue;
                }
                f(addr);
            }
        }
    }
}

pub fn vendor_id(addr: PciAddress) -> u16 {
    read_u16(addr, 0x00)
}

pub fn device_id(addr: PciAddress) -> u16 {
    read_u16(addr, 0x02)
}

pub fn class_code(addr: PciAddress) -> u8 {
    read_u8(addr, 0x0B)
}

pub fn subclass(addr: PciAddress) -> u8 {
    read_u8(addr, 0x0A)
}

pub fn prog_if(addr: PciAddress) -> u8 {
    read_u8(addr, 0x09)
}

pub fn capabilities_pointer(addr: PciAddress) -> Option<u8> {
    let status = read_u16(addr, 0x06);
    if status & (1 << 4) == 0 {
        return None;
    }
    Some(read_u8(addr, 0x34))
}

pub fn find_capability(addr: PciAddress, target: u8) -> Option<u8> {
    let mut cap = capabilities_pointer(addr)?;
    let mut guard = 0;
    while cap != 0 && guard < 64 {
        if read_capability_byte(addr, cap, 0) == target {
            return Some(cap);
        }
        cap = read_capability_byte(addr, cap, 1);
        guard += 1;
    }
    None
}

pub fn read_capability_dword(addr: PciAddress, cap: u8, offset: u8) -> u32 {
    read_u32(addr, cap as u16 + offset as u16)
}

pub fn read_capability_byte(addr: PciAddress, cap: u8, offset: u8) -> u8 {
    read_u8(addr, cap as u16 + offset as u16)
}

pub fn read_capability_word(addr: PciAddress, cap: u8, offset: u8) -> u16 {
    read_u16(addr, cap as u16 + offset as u16)
}

pub fn write_capability_word(addr: PciAddress, cap: u8, offset: u8, value: u16) {
    write_u16(addr, cap as u16 + offset as u16, value)
}
