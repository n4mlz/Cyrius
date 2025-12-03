use alloc::vec::Vec;
use core::convert::TryFrom;
use core::ptr::NonNull;

use crate::arch::x86_64::pci::{self, BarAddress, PciAddress};
use crate::arch::{
    Arch,
    api::{ArchInterrupt, MsiMessage},
};
use crate::device::virtio::queue::QueueConfig;
use crate::device::virtio::transport::{
    DeviceStatus, QueueNotifier, Transport, TransportError, VirtioIrqError, VirtioIrqTransport,
};
use crate::mem::addr::{Addr, PhysAddr, VirtAddr, VirtIntoPtr};
use crate::mem::manager;
use crate::mem::paging::PhysMapper;
use crate::util::spinlock::SpinLock;

const PCI_CAP_ID_VENDOR: u8 = 0x09;
const PCI_CAP_ID_MSIX: u8 = 0x11;
const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
const VIRTIO_BLOCK_DEVICE_ID: u16 = 0x1042;
const MSIX_ENABLE: u16 = 1 << 15;
const MSIX_FUNCTION_MASK: u16 = 1 << 14;
const MSIX_VECTOR_MASK: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioDeviceKind {
    Block,
    Other(u16),
}

impl VirtioDeviceKind {
    pub fn from_device_id(id: u16) -> Self {
        match id {
            VIRTIO_BLOCK_DEVICE_ID => Self::Block,
            other => Self::Other(other),
        }
    }
}

pub struct VirtioPciTransport {
    #[allow(dead_code)]
    addr: PciAddress,
    device_id: u16,
    common: CommonCfg,
    notify: NotifyRegion,
    isr: MmioRegister<u8>,
    device_cfg: DeviceCfgRegion,
    num_queues: u16,
    msix: Option<SpinLock<MsixState>>,
}

unsafe impl Send for VirtioPciTransport {}

impl VirtioPciTransport {
    pub fn probe(addr: PciAddress) -> Result<Self, ProbeError> {
        if pci::vendor_id(addr) != VIRTIO_VENDOR_ID {
            return Err(ProbeError::NotVirtio);
        }

        let device_id = pci::device_id(addr);
        let caps_ptr = pci::capabilities_pointer(addr).ok_or(ProbeError::NoCapabilities)?;
        let caps = VirtioCapSet::discover(addr, caps_ptr)?;

        pci::enable_bus_mastering(addr);

        let common = map_cap_region(addr, caps.common.ok_or(ProbeError::MissingCap("common"))?)?;
        let notify_cap = caps.notify.ok_or(ProbeError::MissingCap("notify"))?;
        let notify_region = map_notify_region(addr, notify_cap)?;
        let isr =
            map_cap_region(addr, caps.isr.ok_or(ProbeError::MissingCap("isr"))?)?.into_register();
        let device_cfg =
            map_cap_region(addr, caps.device.ok_or(ProbeError::MissingCap("device"))?)?;

        let common = CommonCfg::new(common)?;
        let num_queues = common.num_queues();
        let msix = MsixState::discover(addr)?;

        Ok(Self {
            addr,
            device_id,
            common,
            notify: notify_region,
            isr,
            device_cfg: DeviceCfgRegion::from(device_cfg),
            num_queues,
            msix: msix.map(SpinLock::new),
        })
    }

    pub fn kind(&self) -> VirtioDeviceKind {
        VirtioDeviceKind::from_device_id(self.device_id)
    }

    pub fn device_config(&self) -> &DeviceCfgRegion {
        &self.device_cfg
    }

    pub fn isr_status(&self) -> u8 {
        self.isr.read()
    }
}

impl QueueNotifier for VirtioPciTransport {
    fn notify_queue(&self, queue_index: u16) -> Result<(), TransportError> {
        self.select_queue(queue_index)?;
        let offset = self.common.queue_notify_offset();
        self.notify.notify(offset, queue_index)
    }
}

impl Transport for VirtioPciTransport {
    fn device_id(&self) -> u16 {
        self.device_id
    }

    fn read_device_features(&self, select: u32) -> u32 {
        self.common.set_device_feature_select(select);
        self.common.device_feature()
    }

    fn write_driver_features(&self, select: u32, value: u32) {
        self.common.set_driver_feature_select(select);
        self.common.set_driver_feature(value);
    }

    fn num_queues(&self) -> u16 {
        self.num_queues
    }

    fn status(&self) -> DeviceStatus {
        DeviceStatus::from_bits_truncate(self.common.device_status())
    }

    fn set_status(&self, status: DeviceStatus) {
        self.common.set_device_status(status.bits());
    }

    fn config_generation(&self) -> u8 {
        self.common.config_generation()
    }

    fn select_queue(&self, queue_index: u16) -> Result<(), TransportError> {
        if queue_index >= self.num_queues {
            return Err(TransportError::QueueUnavailable);
        }
        self.common.set_queue_select(queue_index);
        Ok(())
    }

    fn queue_size(&self) -> Result<u16, TransportError> {
        Ok(self.common.queue_size())
    }

    fn set_queue_size(&self, size: u16) -> Result<(), TransportError> {
        self.common.set_queue_size(size);
        Ok(())
    }

    fn program_queue(&self, cfg: &QueueConfig) -> Result<(), TransportError> {
        self.common.set_queue_descriptors(cfg.descriptor_area);
        self.common.set_queue_available(cfg.avail_area);
        self.common.set_queue_used(cfg.used_area);
        Ok(())
    }

    fn enable_queue(&self, enabled: bool) -> Result<(), TransportError> {
        self.common.set_queue_enable(enabled);
        Ok(())
    }
}

impl VirtioIrqTransport for VirtioPciTransport {
    fn supports_queue_irq(&self) -> bool {
        self.msix.is_some()
    }

    fn configure_queue_irq(&self, queue_index: u16, vector: u8) -> Result<(), VirtioIrqError> {
        let msix = self.msix.as_ref().ok_or(VirtioIrqError::Unsupported)?;
        let message = <Arch as ArchInterrupt>::msi_message(vector)
            .ok_or(VirtioIrqError::Backend("msi message unavailable"))?;

        let mut state = msix.lock();
        state.enable().map_err(VirtioIrqError::from)?;
        state
            .program_entry(0, message)
            .map_err(VirtioIrqError::from)?;
        self.select_queue(queue_index)
            .map_err(VirtioIrqError::from)?;
        self.common.set_queue_msix_vector(0);
        self.common.set_msix_config_vector(u16::MAX);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ProbeError {
    NotVirtio,
    NoCapabilities,
    MissingCap(&'static str),
    UnsupportedBar(u8),
    AddressOverflow,
    MapFailed,
}

#[derive(Clone, Copy)]
struct CapLocation {
    bar: u8,
    offset: u32,
    length: u32,
}

#[derive(Clone, Copy)]
struct NotifyLocation {
    cap: CapLocation,
    multiplier: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MsixError {
    InvalidIndex,
}

impl From<MsixError> for VirtioIrqError {
    fn from(value: MsixError) -> Self {
        match value {
            MsixError::InvalidIndex => VirtioIrqError::Backend("invalid MSI-X index"),
        }
    }
}

struct MsixState {
    addr: PciAddress,
    cap_ptr: u8,
    table: MsixTable,
    enabled: bool,
}

impl MsixState {
    fn discover(addr: PciAddress) -> Result<Option<Self>, ProbeError> {
        let cap_ptr = match pci::find_capability(addr, PCI_CAP_ID_MSIX) {
            Some(ptr) => ptr,
            None => return Ok(None),
        };

        let msg_control = pci::read_capability_word(addr, cap_ptr, 2);
        let table_size = ((msg_control & 0x07FF) + 1) as usize;
        if table_size == 0 {
            return Ok(None);
        }

        let table_raw = pci::read_capability_dword(addr, cap_ptr, 4);
        let table_bir = (table_raw & 0x7) as u8;
        let table_offset = table_raw & !0x7;
        let table_len = table_size * core::mem::size_of::<MsixTableEntry>();
        let table_region = map_bar_region(addr, table_bir, table_offset, table_len)?;
        let table = MsixTable::new(table_region, table_size)?;

        Ok(Some(Self {
            addr,
            cap_ptr,
            table,
            enabled: false,
        }))
    }

    fn enable(&mut self) -> Result<(), MsixError> {
        if self.enabled {
            return Ok(());
        }
        let mut control = pci::read_capability_word(self.addr, self.cap_ptr, 2);
        control |= MSIX_ENABLE;
        control &= !MSIX_FUNCTION_MASK;
        pci::write_capability_word(self.addr, self.cap_ptr, 2, control);
        self.enabled = true;
        Ok(())
    }

    fn program_entry(&mut self, index: u16, message: MsiMessage) -> Result<(), MsixError> {
        self.table.program(index, message)
    }
}

struct MsixTable {
    _region: MmioRegion,
    entries: *mut MsixTableEntry,
    len: usize,
}

impl MsixTable {
    fn new(region: MmioRegion, len: usize) -> Result<Self, ProbeError> {
        let needed = len
            .checked_mul(core::mem::size_of::<MsixTableEntry>())
            .ok_or(ProbeError::MapFailed)?;
        if region.len < needed {
            return Err(ProbeError::MapFailed);
        }
        let entries = region.virt.into_mut_ptr() as *mut MsixTableEntry;
        Ok(Self {
            _region: region,
            entries,
            len,
        })
    }

    fn program(&mut self, index: u16, message: MsiMessage) -> Result<(), MsixError> {
        let idx = index as usize;
        if idx >= self.len {
            return Err(MsixError::InvalidIndex);
        }
        unsafe {
            let entry = self.entries.add(idx);
            core::ptr::write_volatile(&mut (*entry).addr_lo, message.address as u32);
            core::ptr::write_volatile(&mut (*entry).addr_hi, (message.address >> 32) as u32);
            core::ptr::write_volatile(&mut (*entry).data, message.data);
            let mut ctrl = core::ptr::read_volatile(&(*entry).vector_control);
            ctrl &= !MSIX_VECTOR_MASK;
            core::ptr::write_volatile(&mut (*entry).vector_control, ctrl);
        }
        Ok(())
    }
}

#[repr(C)]
struct MsixTableEntry {
    addr_lo: u32,
    addr_hi: u32,
    data: u32,
    vector_control: u32,
}

struct VirtioCapSet {
    common: Option<CapLocation>,
    notify: Option<NotifyLocation>,
    isr: Option<CapLocation>,
    device: Option<CapLocation>,
}

impl VirtioCapSet {
    fn discover(addr: PciAddress, mut cap_ptr: u8) -> Result<Self, ProbeError> {
        let mut caps = Self {
            common: None,
            notify: None,
            isr: None,
            device: None,
        };

        let mut guard = 0;
        while cap_ptr != 0 {
            if guard > 64 {
                break;
            }
            guard += 1;

            let cap_id = pci::read_capability_byte(addr, cap_ptr, 0);
            let next = pci::read_capability_byte(addr, cap_ptr, 1);
            let cap_len = pci::read_capability_byte(addr, cap_ptr, 2);

            if cap_id == PCI_CAP_ID_VENDOR && cap_len >= 16 {
                let cfg_type = pci::read_capability_byte(addr, cap_ptr, 3);
                let bar = pci::read_capability_byte(addr, cap_ptr, 4);
                let offset = pci::read_capability_dword(addr, cap_ptr, 8);
                let length = pci::read_capability_dword(addr, cap_ptr, 12);
                let location = CapLocation {
                    bar,
                    offset,
                    length,
                };

                match VirtioCfgType::try_from(cfg_type) {
                    Ok(VirtioCfgType::Common) => caps.common = Some(location),
                    Ok(VirtioCfgType::Notify) => {
                        if cap_len >= 20 {
                            let multiplier = pci::read_capability_dword(addr, cap_ptr, 16);
                            caps.notify = Some(NotifyLocation {
                                cap: location,
                                multiplier,
                            });
                        }
                    }
                    Ok(VirtioCfgType::Isr) => caps.isr = Some(location),
                    Ok(VirtioCfgType::Device) => caps.device = Some(location),
                    _ => {}
                }
            }

            if next == 0 {
                break;
            }
            cap_ptr = next;
        }

        Ok(caps)
    }
}

#[repr(u8)]
enum VirtioCfgType {
    Common = 1,
    Notify = 2,
    Isr = 3,
    Device = 4,
    Pci = 5,
}

impl TryFrom<u8> for VirtioCfgType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Common),
            2 => Ok(Self::Notify),
            3 => Ok(Self::Isr),
            4 => Ok(Self::Device),
            5 => Ok(Self::Pci),
            _ => Err(()),
        }
    }
}

struct MmioRegion {
    #[allow(dead_code)]
    phys: PhysAddr,
    virt: VirtAddr,
    len: usize,
}

impl MmioRegion {
    fn into_register<T>(self) -> MmioRegister<T> {
        unsafe { MmioRegister::new(self.virt) }
    }
}

struct NotifyRegion {
    region: MmioRegion,
    multiplier: u32,
}

impl NotifyRegion {
    fn notify(&self, queue_notify_off: u16, queue_index: u16) -> Result<(), TransportError> {
        let offset = (queue_notify_off as u32)
            .checked_mul(self.multiplier)
            .ok_or(TransportError::NotifyUnavailable)? as usize;
        let needed = offset + core::mem::size_of::<u16>();
        if needed > self.region.len {
            return Err(TransportError::NotifyUnavailable);
        }
        let ptr = unsafe { self.region.virt.into_mut_ptr().add(offset) } as *mut u16;
        unsafe {
            core::ptr::write_volatile(ptr, queue_index);
        }
        Ok(())
    }
}

pub struct DeviceCfgRegion {
    base: VirtAddr,
    len: usize,
}

impl DeviceCfgRegion {
    fn from(region: MmioRegion) -> Self {
        Self {
            base: region.virt,
            len: region.len,
        }
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.base.into_mut_ptr()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn read<T: Copy>(&self) -> T {
        assert!(
            core::mem::size_of::<T>() <= self.len,
            "device config too small"
        );
        unsafe { core::ptr::read_volatile(self.base.into_ptr() as *const T) }
    }
}

struct MmioRegister<T> {
    ptr: NonNull<T>,
}

impl<T> MmioRegister<T> {
    unsafe fn new(addr: VirtAddr) -> Self {
        let ptr = NonNull::new(addr.into_mut_ptr() as *mut T).expect("null MMIO pointer");
        Self { ptr }
    }

    fn read(&self) -> T
    where
        T: Copy,
    {
        unsafe { core::ptr::read_volatile(self.ptr.as_ptr()) }
    }

    #[allow(dead_code)]
    fn write(&self, value: T) {
        unsafe { core::ptr::write_volatile(self.ptr.as_ptr(), value) }
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
    queue_desc_lo: u32,
    queue_desc_hi: u32,
    queue_avail_lo: u32,
    queue_avail_hi: u32,
    queue_used_lo: u32,
    queue_used_hi: u32,
}

struct CommonCfg {
    raw: NonNull<VirtioPciCommonCfg>,
}

impl CommonCfg {
    fn new(region: MmioRegion) -> Result<Self, ProbeError> {
        if region.len < core::mem::size_of::<VirtioPciCommonCfg>() {
            return Err(ProbeError::MapFailed);
        }
        Ok(Self {
            raw: NonNull::new(region.virt.into_mut_ptr() as *mut VirtioPciCommonCfg)
                .ok_or(ProbeError::MapFailed)?,
        })
    }

    fn num_queues(&self) -> u16 {
        unsafe { core::ptr::read_volatile(&(*self.raw.as_ptr()).num_queues) }
    }

    fn device_status(&self) -> u8 {
        unsafe { core::ptr::read_volatile(&(*self.raw.as_ptr()).device_status) }
    }

    fn set_device_status(&self, value: u8) {
        unsafe { core::ptr::write_volatile(&mut (*self.raw.as_ptr()).device_status, value) }
    }

    fn config_generation(&self) -> u8 {
        unsafe { core::ptr::read_volatile(&(*self.raw.as_ptr()).config_generation) }
    }

    fn set_device_feature_select(&self, value: u32) {
        unsafe { core::ptr::write_volatile(&mut (*self.raw.as_ptr()).device_feature_select, value) }
    }

    fn device_feature(&self) -> u32 {
        unsafe { core::ptr::read_volatile(&(*self.raw.as_ptr()).device_feature) }
    }

    fn set_driver_feature_select(&self, value: u32) {
        unsafe { core::ptr::write_volatile(&mut (*self.raw.as_ptr()).driver_feature_select, value) }
    }

    fn set_driver_feature(&self, value: u32) {
        unsafe { core::ptr::write_volatile(&mut (*self.raw.as_ptr()).driver_feature, value) }
    }

    fn set_queue_select(&self, value: u16) {
        unsafe { core::ptr::write_volatile(&mut (*self.raw.as_ptr()).queue_select, value) }
    }

    fn queue_size(&self) -> u16 {
        unsafe { core::ptr::read_volatile(&(*self.raw.as_ptr()).queue_size) }
    }

    fn set_queue_size(&self, value: u16) {
        unsafe { core::ptr::write_volatile(&mut (*self.raw.as_ptr()).queue_size, value) }
    }

    fn set_queue_enable(&self, enabled: bool) {
        unsafe { core::ptr::write_volatile(&mut (*self.raw.as_ptr()).queue_enable, enabled as u16) }
    }

    fn set_queue_msix_vector(&self, value: u16) {
        unsafe { core::ptr::write_volatile(&mut (*self.raw.as_ptr()).queue_msix_vector, value) }
    }

    fn set_msix_config_vector(&self, value: u16) {
        unsafe { core::ptr::write_volatile(&mut (*self.raw.as_ptr()).msix_config, value) }
    }

    fn queue_notify_offset(&self) -> u16 {
        unsafe { core::ptr::read_volatile(&(*self.raw.as_ptr()).queue_notify_off) }
    }

    fn set_queue_descriptors(&self, addr: PhysAddr) {
        self.write_address(|cfg| (&mut cfg.queue_desc_lo, &mut cfg.queue_desc_hi), addr);
    }

    fn set_queue_available(&self, addr: PhysAddr) {
        self.write_address(
            |cfg| (&mut cfg.queue_avail_lo, &mut cfg.queue_avail_hi),
            addr,
        );
    }

    fn set_queue_used(&self, addr: PhysAddr) {
        self.write_address(|cfg| (&mut cfg.queue_used_lo, &mut cfg.queue_used_hi), addr);
    }

    fn write_address(
        &self,
        mut fields: impl FnMut(&mut VirtioPciCommonCfg) -> (&mut u32, &mut u32),
        addr: PhysAddr,
    ) {
        let raw = addr.as_raw() as u64;
        unsafe {
            let cfg = self.raw.as_ptr();
            let (lo, hi) = fields(&mut *cfg);
            core::ptr::write_volatile(lo, raw as u32);
            core::ptr::write_volatile(hi, (raw >> 32) as u32);
        }
    }
}

fn map_cap_region(addr: PciAddress, cap: CapLocation) -> Result<MmioRegion, ProbeError> {
    let bar = pci::read_bar(addr, cap.bar).ok_or(ProbeError::UnsupportedBar(cap.bar))?;
    let base = match bar {
        BarAddress::Memory { base } => base,
        BarAddress::Io { .. } => return Err(ProbeError::UnsupportedBar(cap.bar)),
    };
    let phys = base
        .checked_add(cap.offset as usize)
        .ok_or(ProbeError::AddressOverflow)?;
    let len = cap.length as usize;
    if len == 0 {
        return Err(ProbeError::MapFailed);
    }
    let mapper = manager::phys_mapper();
    let virt = unsafe { mapper.phys_to_virt(phys) };
    Ok(MmioRegion { phys, virt, len })
}

fn map_notify_region(addr: PciAddress, notify: NotifyLocation) -> Result<NotifyRegion, ProbeError> {
    let region = map_cap_region(addr, notify.cap)?;
    Ok(NotifyRegion {
        region,
        multiplier: notify.multiplier,
    })
}

fn map_bar_region(
    addr: PciAddress,
    bar: u8,
    offset: u32,
    len: usize,
) -> Result<MmioRegion, ProbeError> {
    let cap = CapLocation {
        bar,
        offset,
        length: len.try_into().map_err(|_| ProbeError::AddressOverflow)?,
    };
    map_cap_region(addr, cap)
}

pub fn enumerate_block_transports() -> Vec<VirtioPciTransport> {
    let mut transports = Vec::new();
    pci::enumerate(|addr| {
        if pci::vendor_id(addr) != VIRTIO_VENDOR_ID {
            return;
        }
        if pci::device_id(addr) != VIRTIO_BLOCK_DEVICE_ID {
            return;
        }
        if let Ok(tx) = VirtioPciTransport::probe(addr) {
            transports.push(tx);
        }
    });
    transports
}
