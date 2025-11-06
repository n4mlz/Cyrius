use core::mem::size_of;

use crate::device::virtio::queue::VirtQueueRegion;
use crate::mem::addr::{Addr, PhysAddr, VirtAddr, VirtIntoPtr};

/// Memory-mapped configuration space for a VirtIO device.
#[derive(Clone, Copy, Debug)]
pub struct MmioConfig {
    base: VirtAddr,
    length: usize,
}

impl MmioConfig {
    /// # Safety
    ///
    /// Caller must ensure the provided address range is mapped as a VirtIO MMIO configuration
    /// structure and that concurrent access obeys device-specific synchronisation rules.
    pub const unsafe fn new(base: VirtAddr, length: usize) -> Self {
        Self { base, length }
    }

    fn ptr<T>(&self, offset: usize) -> Result<*mut T, MmioError> {
        let width = size_of::<T>();
        let end = offset
            .checked_add(width)
            .ok_or(MmioError::AddressOverflow { offset, width })?;
        if end > self.length {
            return Err(MmioError::OutOfRange { offset, width });
        }
        let addr = self
            .base
            .checked_add(offset)
            .ok_or(MmioError::AddressOverflow { offset, width })?;
        Ok(addr.into_mut_ptr() as *mut T)
    }
}

/// Safe wrapper around the VirtIO MMIO register map.
#[derive(Clone, Copy, Debug)]
pub struct MmioDevice {
    cfg: MmioConfig,
}

impl MmioDevice {
    const MAGIC_VALUE: u32 = 0x7472_6976;
    const HEADER_LEN: usize = 0x100;

    const REG_MAGIC: usize = 0x000;
    const REG_VERSION: usize = 0x004;
    const REG_DEVICE_ID: usize = 0x008;
    const REG_VENDOR_ID: usize = 0x00c;
    const REG_DEVICE_FEATURES: usize = 0x010;
    const REG_DEVICE_FEATURES_SEL: usize = 0x014;
    const REG_DRIVER_FEATURES: usize = 0x020;
    const REG_DRIVER_FEATURES_SEL: usize = 0x024;
    const REG_QUEUE_SEL: usize = 0x030;
    const REG_QUEUE_NUM_MAX: usize = 0x034;
    const REG_QUEUE_NUM: usize = 0x038;
    const REG_QUEUE_READY: usize = 0x044;
    const REG_QUEUE_NOTIFY: usize = 0x050;
    const REG_INTERRUPT_STATUS: usize = 0x060;
    const REG_INTERRUPT_ACK: usize = 0x064;
    const REG_STATUS: usize = 0x070;
    const REG_QUEUE_DESC_LOW: usize = 0x080;
    const REG_QUEUE_DESC_HIGH: usize = 0x084;
    const REG_QUEUE_DRIVER_LOW: usize = 0x090;
    const REG_QUEUE_DRIVER_HIGH: usize = 0x094;
    const REG_QUEUE_DEVICE_LOW: usize = 0x0a0;
    const REG_QUEUE_DEVICE_HIGH: usize = 0x0a4;

    /// Attempt to build a wrapper around the provided configuration mapping.
    pub fn from_config(cfg: MmioConfig) -> Result<Self, MmioError> {
        if cfg.length < Self::HEADER_LEN {
            return Err(MmioError::OutOfRange {
                offset: 0,
                width: Self::HEADER_LEN,
            });
        }
        let dev = Self { cfg };
        dev.verify()?;
        Ok(dev)
    }

    fn verify(&self) -> Result<(), MmioError> {
        let magic = self.read32(Self::REG_MAGIC)?;
        if magic != Self::MAGIC_VALUE {
            return Err(MmioError::UnexpectedMagic { found: magic });
        }
        let version = self.read32(Self::REG_VERSION)?;
        if version < 2 {
            return Err(MmioError::UnsupportedVersion { found: version });
        }
        Ok(())
    }

    fn read32(&self, offset: usize) -> Result<u32, MmioError> {
        let ptr = self.cfg.ptr::<u32>(offset)?;
        // SAFETY: range checked above.
        Ok(unsafe { core::ptr::read_volatile(ptr) })
    }

    fn write32(&self, offset: usize, value: u32) -> Result<(), MmioError> {
        let ptr = self.cfg.ptr::<u32>(offset)?;
        // SAFETY: range checked above.
        unsafe { core::ptr::write_volatile(ptr, value) };
        Ok(())
    }

    pub fn device_id(&self) -> Result<u32, MmioError> {
        self.read32(Self::REG_DEVICE_ID)
    }

    pub fn vendor_id(&self) -> Result<u32, MmioError> {
        self.read32(Self::REG_VENDOR_ID)
    }

    pub fn read_device_features(&self) -> Result<u64, MmioError> {
        let mut value = 0u64;
        for sel in 0..2u32 {
            self.write32(Self::REG_DEVICE_FEATURES_SEL, sel)?;
            let part = self.read32(Self::REG_DEVICE_FEATURES)? as u64;
            value |= part << (sel * 32);
        }
        Ok(value)
    }

    pub fn write_driver_features(&self, features: u64) -> Result<(), MmioError> {
        for sel in 0..2u32 {
            self.write32(Self::REG_DRIVER_FEATURES_SEL, sel)?;
            let part = ((features >> (sel * 32)) & 0xFFFF_FFFF) as u32;
            self.write32(Self::REG_DRIVER_FEATURES, part)?;
        }
        Ok(())
    }

    pub fn status(&self) -> Result<u32, MmioError> {
        self.read32(Self::REG_STATUS)
    }

    pub fn set_status(&self, status: u32) -> Result<(), MmioError> {
        self.write32(Self::REG_STATUS, status)
    }

    pub fn select_queue(&self, index: u16) -> Result<(), MmioError> {
        self.write32(Self::REG_QUEUE_SEL, index as u32)
    }

    pub fn queue_size_max(&self) -> Result<u16, MmioError> {
        Ok(self.read32(Self::REG_QUEUE_NUM_MAX)? as u16)
    }

    pub fn set_queue_size(&self, size: u16) -> Result<(), MmioError> {
        self.write32(Self::REG_QUEUE_NUM, size as u32)
    }

    pub fn set_queue_ready(&self, ready: bool) -> Result<(), MmioError> {
        self.write32(Self::REG_QUEUE_READY, if ready { 1 } else { 0 })
    }

    pub fn is_queue_ready(&self) -> Result<bool, MmioError> {
        Ok(self.read32(Self::REG_QUEUE_READY)? != 0)
    }

    pub fn configure_queue(&self, region: VirtQueueRegion) -> Result<(), MmioError> {
        self.write64(
            Self::REG_QUEUE_DESC_LOW,
            Self::REG_QUEUE_DESC_HIGH,
            region.descriptor,
        )?;
        self.write64(
            Self::REG_QUEUE_DRIVER_LOW,
            Self::REG_QUEUE_DRIVER_HIGH,
            region.driver,
        )?;
        self.write64(
            Self::REG_QUEUE_DEVICE_LOW,
            Self::REG_QUEUE_DEVICE_HIGH,
            region.device,
        )?;
        Ok(())
    }

    pub fn acknowledge_interrupts(&self) -> Result<u32, MmioError> {
        let status = self.read32(Self::REG_INTERRUPT_STATUS)?;
        if status != 0 {
            self.write32(Self::REG_INTERRUPT_ACK, status)?;
        }
        Ok(status)
    }

    pub fn notify_queue(&self, queue_index: u16) -> Result<(), MmioError> {
        self.write32(Self::REG_QUEUE_NOTIFY, queue_index as u32)
    }

    pub fn read_config<T>(&self, offset: usize) -> Result<T, MmioError>
    where
        T: Copy,
    {
        let ptr = self.cfg.ptr::<T>(Self::HEADER_LEN + offset)?;
        // SAFETY: range checked above.
        Ok(unsafe { core::ptr::read_volatile(ptr) })
    }

    fn write64(
        &self,
        low_offset: usize,
        high_offset: usize,
        addr: PhysAddr,
    ) -> Result<(), MmioError> {
        let raw = addr.as_raw() as u64;
        self.write32(low_offset, raw as u32)?;
        self.write32(high_offset, (raw >> 32) as u32)
    }
}

#[derive(Debug)]
pub enum MmioError {
    OutOfRange { offset: usize, width: usize },
    AddressOverflow { offset: usize, width: usize },
    UnexpectedMagic { found: u32 },
    UnsupportedVersion { found: u32 },
}
