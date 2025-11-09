use alloc::vec::Vec;
use core::{convert::TryFrom, mem::size_of, ptr::NonNull};

use crate::device::bus::pci::PciAddress;
use crate::device::virtio::queue::VirtQueueRegion;
use crate::mem::addr::{Addr, VirtAddr, VirtIntoPtr};
use crate::mem::manager;
use crate::mem::paging::PhysMapper;

const CAP_ID_VENDOR: u8 = 0x09;
const CFG_TYPE_COMMON: u8 = 1;
const CFG_TYPE_NOTIFY: u8 = 2;
const CFG_TYPE_ISR: u8 = 3;
const CFG_TYPE_DEVICE: u8 = 4;

const CAP_LEN_BASE: u8 = 16;
const CAP_LEN_NOTIFY: u8 = 20;

/// Provides access to a VirtIO device exposed via the modern PCI transport.
///
/// # Notes
/// - Assumes `mem::manager::phys_mapper()` offers a direct offset mapping for PCI BARs.
/// - Callers must ensure exclusive access when issuing concurrent transport operations.
pub struct PciTransport {
    address: PciAddress,
    common_cfg: NonNull<VirtioPciCommonCfg>,
    isr_status: NonNull<u8>,
    device_cfg: VirtAddr,
    device_cfg_len: usize,
    notify_addrs: Vec<Option<VirtAddr>>,
    queue_count: u16,
}

impl PciTransport {
    pub fn new(address: PciAddress) -> Result<Self, PciTransportError> {
        address.enable_bus_master_and_mem();

        let caps = VirtioCapabilitySet::discover(&address)?;

        let common_region = map_region(&address, &caps.common)?;
        if common_region.len < size_of::<VirtioPciCommonCfg>() {
            return Err(PciTransportError::CapabilityTooSmall {
                capability: "common",
                required: size_of::<VirtioPciCommonCfg>(),
                actual: common_region.len,
            });
        }
        let common_cfg = NonNull::new(common_region.base.into_mut_ptr() as *mut VirtioPciCommonCfg)
            .ok_or(PciTransportError::RegionNotMapped("common"))?;

        let isr_region = map_region(&address, &caps.isr)?;
        if isr_region.len < 1 {
            return Err(PciTransportError::CapabilityTooSmall {
                capability: "isr",
                required: 1,
                actual: isr_region.len,
            });
        }
        let isr_status = NonNull::new(isr_region.base.into_mut_ptr())
            .ok_or(PciTransportError::RegionNotMapped("isr"))?;

        let device_region = map_region(&address, &caps.device)?;
        if device_region.len == 0 {
            return Err(PciTransportError::CapabilityTooSmall {
                capability: "device",
                required: 1,
                actual: 0,
            });
        }

        let notify_region = map_region(&address, &caps.notify.cap)?;
        if notify_region.len == 0 {
            return Err(PciTransportError::CapabilityTooSmall {
                capability: "notify",
                required: 2,
                actual: 0,
            });
        }

        let queue_count = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!((*common_cfg.as_ptr()).num_queues))
        };
        if queue_count == 0 {
            return Err(PciTransportError::NoQueuesExposed);
        }

        let mut notify_addrs = Vec::with_capacity(queue_count as usize);
        notify_addrs.resize(queue_count as usize, None);

        let multiplier = usize::try_from(caps.notify.notify_off_multiplier)
            .map_err(|_| PciTransportError::CapabilityPointerOverflow)?;
        let notify_len = notify_region.len;

        for queue in 0..queue_count {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!((*common_cfg.as_ptr()).queue_select),
                    queue,
                );
                let off = core::ptr::read_volatile(core::ptr::addr_of!(
                    (*common_cfg.as_ptr()).queue_notify_off
                )) as usize;

                let stride = off
                    .checked_mul(multiplier)
                    .ok_or(PciTransportError::NotifyOffsetOverflow { queue })?;

                if stride.checked_add(2).map_or(true, |end| end > notify_len) {
                    return Err(PciTransportError::NotifyOffsetOutOfRange {
                        queue,
                        offset: stride,
                        region_len: notify_len,
                    });
                }

                let doorbell = notify_region
                    .base
                    .checked_add(stride)
                    .ok_or(PciTransportError::NotifyAddressOverflow { queue })?;

                notify_addrs[queue as usize] = Some(doorbell);
            }
        }

        // Restore queue_select to zero for callers expecting a default.
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*common_cfg.as_ptr()).queue_select),
                0,
            );
        }

        Ok(Self {
            address,
            common_cfg,
            isr_status,
            device_cfg: device_region.base,
            device_cfg_len: device_region.len,
            notify_addrs,
            queue_count,
        })
    }

    pub fn read_device_features(&self) -> Result<u64, PciTransportError> {
        let mut value = 0u64;
        for sel in 0..2u32 {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!((*self.common_cfg.as_ptr()).device_feature_select),
                    sel,
                );
                let part = core::ptr::read_volatile(core::ptr::addr_of!(
                    (*self.common_cfg.as_ptr()).device_feature
                )) as u64;
                value |= part << (sel * 32);
            }
        }
        Ok(value)
    }

    pub fn write_driver_features(&self, features: u64) -> Result<(), PciTransportError> {
        for sel in 0..2u32 {
            unsafe {
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!((*self.common_cfg.as_ptr()).driver_feature_select),
                    sel,
                );
                let part = ((features >> (sel * 32)) & 0xFFFF_FFFF) as u32;
                core::ptr::write_volatile(
                    core::ptr::addr_of_mut!((*self.common_cfg.as_ptr()).driver_feature),
                    part,
                );
            }
        }
        Ok(())
    }

    pub fn set_status(&self, status: u32) -> Result<(), PciTransportError> {
        let value = (status & 0xFF) as u8;
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*self.common_cfg.as_ptr()).device_status),
                value,
            );
        }
        Ok(())
    }

    pub fn status(&self) -> Result<u32, PciTransportError> {
        let value = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(
                (*self.common_cfg.as_ptr()).device_status
            ))
        };
        Ok(value as u32)
    }

    pub fn select_queue(&self, index: u16) -> Result<(), PciTransportError> {
        if index >= self.queue_count {
            return Err(PciTransportError::QueueIndexOutOfRange {
                index,
                available: self.queue_count,
            });
        }
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*self.common_cfg.as_ptr()).queue_select),
                index,
            );
        }
        Ok(())
    }

    pub fn queue_size_max(&self) -> Result<u16, PciTransportError> {
        let size = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!((*self.common_cfg.as_ptr()).queue_size))
        };
        Ok(size)
    }

    pub fn set_queue_size(&self, size: u16) -> Result<(), PciTransportError> {
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*self.common_cfg.as_ptr()).queue_size),
                size,
            );
        }
        Ok(())
    }

    pub fn configure_queue(&self, region: VirtQueueRegion) -> Result<(), PciTransportError> {
        unsafe {
            write_split_u64(
                core::ptr::addr_of_mut!((*self.common_cfg.as_ptr()).queue_desc_lo),
                region.descriptor.as_raw() as u64,
            );
            write_split_u64(
                core::ptr::addr_of_mut!((*self.common_cfg.as_ptr()).queue_avail_lo),
                region.driver.as_raw() as u64,
            );
            write_split_u64(
                core::ptr::addr_of_mut!((*self.common_cfg.as_ptr()).queue_used_lo),
                region.device.as_raw() as u64,
            );
        }
        Ok(())
    }

    pub fn set_queue_ready(&self, ready: bool) -> Result<(), PciTransportError> {
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*self.common_cfg.as_ptr()).queue_enable),
                if ready { 1 } else { 0 },
            );
        }
        Ok(())
    }

    pub fn is_queue_ready(&self) -> Result<bool, PciTransportError> {
        let value = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(
                (*self.common_cfg.as_ptr()).queue_enable
            ))
        };
        Ok(value != 0)
    }

    pub fn notify_queue(&self, queue_index: u16) -> Result<(), PciTransportError> {
        if queue_index >= self.queue_count {
            return Err(PciTransportError::QueueIndexOutOfRange {
                index: queue_index,
                available: self.queue_count,
            });
        }
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*self.common_cfg.as_ptr()).queue_select),
                queue_index,
            );
        }
        let notify_data = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!(
                (*self.common_cfg.as_ptr()).queue_notify_data
            ))
        };

        let doorbell = self
            .notify_addrs
            .get(queue_index as usize)
            .and_then(|entry| *entry)
            .ok_or(PciTransportError::NotifyAddressMissing { queue: queue_index })?;

        unsafe {
            core::ptr::write_volatile(doorbell.into_mut_ptr() as *mut u16, notify_data);
        }
        Ok(())
    }

    pub fn acknowledge_interrupts(&self) -> Result<u32, PciTransportError> {
        let status = unsafe { core::ptr::read_volatile(self.isr_status.as_ptr()) };
        Ok(status as u32)
    }

    pub fn read_config<T>(&self, offset: usize) -> Result<T, PciTransportError>
    where
        T: Copy,
    {
        let size = size_of::<T>();
        if offset
            .checked_add(size)
            .map_or(true, |end| end > self.device_cfg_len)
        {
            return Err(PciTransportError::DeviceConfigOutOfRange { offset, size });
        }

        let ptr = (self.device_cfg.into_ptr() as usize)
            .checked_add(offset)
            .ok_or(PciTransportError::DeviceConfigOutOfRange { offset, size })?
            as *const T;

        // SAFETY: bounds are checked above.
        Ok(unsafe { core::ptr::read_unaligned(ptr) })
    }

    pub fn queue_count(&self) -> u16 {
        self.queue_count
    }

    pub fn pci_address(&self) -> PciAddress {
        self.address
    }
}

#[derive(Debug)]
pub enum PciTransportError {
    CapabilityListMissing,
    CapabilityTraversalLoop,
    MissingCapability(&'static str),
    CapabilityTooSmall {
        capability: &'static str,
        required: usize,
        actual: usize,
    },
    CapabilityPointerOverflow,
    NotifyOffsetOverflow {
        queue: u16,
    },
    NotifyOffsetOutOfRange {
        queue: u16,
        offset: usize,
        region_len: usize,
    },
    NotifyAddressOverflow {
        queue: u16,
    },
    NotifyAddressMissing {
        queue: u16,
    },
    BarUnavailable {
        bar: u8,
    },
    RegionNotMapped(&'static str),
    DeviceConfigOutOfRange {
        offset: usize,
        size: usize,
    },
    QueueIndexOutOfRange {
        index: u16,
        available: u16,
    },
    NoQueuesExposed,
}

impl core::fmt::Display for PciTransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CapabilityListMissing => write!(f, "PCI capability list not supported"),
            Self::CapabilityTraversalLoop => write!(f, "PCI capability traversal loop detected"),
            Self::MissingCapability(name) => write!(f, "required capability '{name}' missing"),
            Self::CapabilityTooSmall {
                capability,
                required,
                actual,
            } => write!(
                f,
                "{capability} capability too small: required {required} bytes, present {actual}"
            ),
            Self::CapabilityPointerOverflow => {
                write!(f, "capability pointer overflowed standard config space")
            }
            Self::NotifyOffsetOverflow { queue } => {
                write!(f, "notify offset multiplication overflow for queue {queue}")
            }
            Self::NotifyOffsetOutOfRange {
                queue,
                offset,
                region_len,
            } => write!(
                f,
                "queue {queue} notify offset {offset} exceeds region length {region_len}"
            ),
            Self::NotifyAddressOverflow { queue } => {
                write!(f, "notify address overflow for queue {queue}")
            }
            Self::NotifyAddressMissing { queue } => {
                write!(f, "notify address missing for queue {queue}")
            }
            Self::BarUnavailable { bar } => write!(f, "BAR{bar} unavailable or not memory-mapped"),
            Self::RegionNotMapped(name) => write!(f, "failed to map {name} capability region"),
            Self::DeviceConfigOutOfRange { offset, size } => write!(
                f,
                "device config read out of range (offset {offset} size {size})"
            ),
            Self::QueueIndexOutOfRange { index, available } => write!(
                f,
                "queue index {index} out of range (available {available})"
            ),
            Self::NoQueuesExposed => write!(f, "device reports zero queues"),
        }
    }
}

struct VirtioCapabilitySet {
    common: VirtioPciCap,
    notify: VirtioPciNotifyCap,
    isr: VirtioPciCap,
    device: VirtioPciCap,
}

impl VirtioCapabilitySet {
    fn discover(address: &PciAddress) -> Result<Self, PciTransportError> {
        let status = address.read_u16(0x06);
        if status & (1 << 4) == 0 {
            return Err(PciTransportError::CapabilityListMissing);
        }

        let mut ptr = address.read_u8(0x34);
        if ptr == 0 {
            return Err(PciTransportError::CapabilityListMissing);
        }

        let mut guard = 0u8;
        let mut common = None;
        let mut notify = None;
        let mut isr = None;
        let mut device = None;

        while ptr != 0 {
            guard = guard.wrapping_add(1);
            if guard == 0 {
                return Err(PciTransportError::CapabilityTraversalLoop);
            }

            let cap_vndr = address.read_u8(ptr);
            let cap_next = address.read_u8(
                ptr.checked_add(1)
                    .ok_or(PciTransportError::CapabilityPointerOverflow)?,
            );
            let cap_len = address.read_u8(
                ptr.checked_add(2)
                    .ok_or(PciTransportError::CapabilityPointerOverflow)?,
            );

            if cap_vndr == CAP_ID_VENDOR {
                if cap_len < CAP_LEN_BASE {
                    return Err(PciTransportError::CapabilityTooSmall {
                        capability: "virtio",
                        required: CAP_LEN_BASE as usize,
                        actual: cap_len as usize,
                    });
                }

                let cfg_type = address.read_u8(
                    ptr.checked_add(3)
                        .ok_or(PciTransportError::CapabilityPointerOverflow)?,
                );
                let bar = address.read_u8(
                    ptr.checked_add(4)
                        .ok_or(PciTransportError::CapabilityPointerOverflow)?,
                );
                let offset = address.read_u32(
                    ptr.checked_add(8)
                        .ok_or(PciTransportError::CapabilityPointerOverflow)?,
                );
                let length = address.read_u32(
                    ptr.checked_add(12)
                        .ok_or(PciTransportError::CapabilityPointerOverflow)?,
                );

                let base = VirtioPciCap {
                    bar,
                    offset,
                    length,
                };

                match cfg_type {
                    CFG_TYPE_COMMON => common = Some(base),
                    CFG_TYPE_NOTIFY => {
                        if cap_len < CAP_LEN_NOTIFY {
                            return Err(PciTransportError::CapabilityTooSmall {
                                capability: "notify",
                                required: CAP_LEN_NOTIFY as usize,
                                actual: cap_len as usize,
                            });
                        }
                        let multiplier = address.read_u32(
                            ptr.checked_add(16)
                                .ok_or(PciTransportError::CapabilityPointerOverflow)?,
                        );
                        notify = Some(VirtioPciNotifyCap {
                            cap: base,
                            notify_off_multiplier: multiplier,
                        });
                    }
                    CFG_TYPE_ISR => isr = Some(base),
                    CFG_TYPE_DEVICE => device = Some(base),
                    _ => {}
                }
            }

            if cap_next == ptr {
                break;
            }
            ptr = cap_next;
        }

        Ok(Self {
            common: common.ok_or(PciTransportError::MissingCapability("common"))?,
            notify: notify.ok_or(PciTransportError::MissingCapability("notify"))?,
            isr: isr.ok_or(PciTransportError::MissingCapability("isr"))?,
            device: device.ok_or(PciTransportError::MissingCapability("device"))?,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct VirtioPciCap {
    bar: u8,
    offset: u32,
    length: u32,
}

#[derive(Clone, Copy, Debug)]
struct VirtioPciNotifyCap {
    cap: VirtioPciCap,
    notify_off_multiplier: u32,
}

#[derive(Clone, Copy, Debug)]
struct MappedRegion {
    base: VirtAddr,
    len: usize,
}

fn map_region(address: &PciAddress, cap: &VirtioPciCap) -> Result<MappedRegion, PciTransportError> {
    let bar_phys = address
        .bar_address(cap.bar)
        .ok_or(PciTransportError::BarUnavailable { bar: cap.bar })?;

    let offset =
        usize::try_from(cap.offset).map_err(|_| PciTransportError::CapabilityPointerOverflow)?;
    let len =
        usize::try_from(cap.length).map_err(|_| PciTransportError::CapabilityPointerOverflow)?;

    let phys = bar_phys
        .checked_add(offset)
        .ok_or(PciTransportError::CapabilityPointerOverflow)?;

    let virt = unsafe { manager::phys_mapper().phys_to_virt(phys) };

    Ok(MappedRegion { base: virt, len })
}

unsafe fn write_split_u64(base: *mut u32, value: u64) {
    unsafe {
        core::ptr::write_volatile(base, value as u32);
        core::ptr::write_volatile(base.add(1), (value >> 32) as u32);
    }
}

#[repr(C)]
struct VirtioPciCommonCfg {
    device_feature_select: u32,
    device_feature: u32,
    driver_feature_select: u32,
    driver_feature: u32,
    msix_config: u16,
    num_queues: u16,
    device_status: u8,
    config_generation: u8,
    queue_select: u16,
    queue_size: u16,
    queue_msix_vector: u16,
    queue_enable: u16,
    queue_notify_off: u16,
    queue_notify_data: u16,
    queue_desc_lo: u32,
    queue_desc_hi: u32,
    queue_avail_lo: u32,
    queue_avail_hi: u32,
    queue_used_lo: u32,
    queue_used_hi: u32,
    queue_reset: u16,
    reserved: u16,
}
