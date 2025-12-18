use alloc::{boxed::Box, format, string::String, sync::Arc, vec::Vec};

use crate::device::block::BlockDevice;
use crate::device::virtio::pci::{self, VirtioPciTransport};
use crate::device::virtio::queue::{
    Descriptor, DescriptorFlags, QueueError, QueueMemory, UsedElem,
};
use crate::device::virtio::transport::{
    DeviceStatus, Transport, TransportError, VirtioIrqError, VirtioIrqTransport,
};
use crate::device::{Device, DeviceType};
use crate::interrupt::{INTERRUPTS, InterruptError, InterruptServiceRoutine};
use crate::mem::addr::{Addr, PageSize, PhysAddr, VirtIntoPtr};
use crate::mem::dma::{DmaError, DmaRegion, DmaRegionProvider};
use crate::trap::{CurrentTrapFrame, TrapInfo};
use crate::util::lazylock::LazyLock;
use crate::util::spinlock::SpinLock;
use core::sync::atomic::{fence, AtomicBool, Ordering};

const VIRTIO_BLK_DEBUG: bool = true;

const VIRTIO_BLOCK_QUEUE_INDEX: u16 = 0;
const MAX_QUEUE_SIZE: u16 = 128;
const MIN_QUEUE_SIZE: u16 = 3;
const VIRTIO_SECTOR_SIZE: u32 = 512;
const DEFAULT_BLOCK_SIZE: u32 = 512;

const fn block_registry_init() -> SpinLock<Vec<Arc<SpinLock<VirtioPciBlkDevice>>>> {
    SpinLock::new(Vec::new())
}

static BLOCK_DEVICES: LazyLock<SpinLock<Vec<Arc<SpinLock<VirtioPciBlkDevice>>>>> =
    LazyLock::new_const(block_registry_init);

fn fail_status<T: Transport>(transport: &mut T, err: VirtioBlkError) -> VirtioBlkError {
    transport.set_status(DeviceStatus::FAILED);
    err
}

pub type VirtioPciBlkDevice = VirtioBlkDevice<VirtioPciTransport>;

pub fn probe_pci_devices() -> usize {
    let transports = pci::enumerate_block_transports();
    let mut guard = BLOCK_DEVICES.get().lock();
    let existing = guard.len();
    let mut added = 0;

    for transport in transports {
        let name = format!("virtio-blk{}", existing + added);
        match VirtioBlkDevice::new(name, transport) {
            Ok(device) => {
                guard.push(Arc::new(SpinLock::new(device)));
                added += 1;
            }
            Err(err) => {
                crate::println!("[blk] failed to initialise virtio device: {err:?}");
            }
        }
    }

    added
}

pub fn with_devices<R>(f: impl FnOnce(&[Arc<SpinLock<VirtioPciBlkDevice>>]) -> R) -> R {
    let guard = BLOCK_DEVICES.get().lock();
    let devices = guard.clone();
    drop(guard);
    f(devices.as_slice())
}

pub trait VirtioBlkTransport: Transport {
    fn read_block_config(&self) -> VirtioBlkConfig;
}

impl VirtioBlkTransport for VirtioPciTransport {
    fn read_block_config(&self) -> VirtioBlkConfig {
        self.device_config().read()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtioBlkConfig {
    pub capacity: u64,
    pub size_max: u32,
    pub seg_max: u32,
    pub geometry: VirtioBlkGeometry,
    pub blk_size: u32,
    pub topology: VirtioBlkTopology,
    pub writeback: u8,
    pub unused0: [u8; 3],
    pub max_discard_sectors: u32,
    pub max_discard_seg: u32,
    pub discard_sector_alignment: u32,
    pub max_write_zeroes_sectors: u32,
    pub max_write_zeroes_seg: u32,
    pub write_zeroes_may_unmap: u8,
    pub unused1: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtioBlkGeometry {
    pub cylinders: u16,
    pub heads: u8,
    pub sectors: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtioBlkTopology {
    pub physical_block_exp: u8,
    pub alignment_offset: u8,
    pub min_io_size: u16,
    pub opt_io_size: u32,
}

pub struct VirtioBlkDevice<T: VirtioBlkTransport> {
    name: String,
    transport: T,
    queue: QueueState,
    dma: DmaRegionProvider,
    block_size: u32,
    capacity_sectors: u64,
    read_only: bool,
    flush_supported: bool,
    queue_irq: Option<&'static QueueInterrupt>,
    irq_handler: Option<&'static QueueInterruptHandler>,
    irq_vector: Option<u8>,
    #[cfg(test)]
    completion_hook: Option<fn(&mut QueueState, &mut RequestBuffers)>,
}

impl<T: VirtioBlkTransport + VirtioIrqTransport> VirtioBlkDevice<T> {
    pub fn new(name: String, mut transport: T) -> Result<Self, VirtioBlkError> {
        let mut status = DeviceStatus::ACKNOWLEDGE;
        transport.set_status(status);
        status = status.with(DeviceStatus::DRIVER);
        transport.set_status(status);

        let device_features = transport.read_device_features(0);
        let driver_features = select_features(device_features);
        transport.write_driver_features(0, driver_features);

        status = status.with(DeviceStatus::FEATURES_OK);
        transport.set_status(status);
        if !transport.status().contains(DeviceStatus::FEATURES_OK) {
            return Err(fail_status(
                &mut transport,
                VirtioBlkError::FeatureNegotiationFailed,
            ));
        }

        transport.select_queue(VIRTIO_BLOCK_QUEUE_INDEX)?;
        let device_queue_size = transport.queue_size()?;
        if device_queue_size < MIN_QUEUE_SIZE {
            return Err(fail_status(
                &mut transport,
                VirtioBlkError::QueueTooSmall(device_queue_size),
            ));
        }
        let queue_size = device_queue_size.min(MAX_QUEUE_SIZE);
        transport.set_queue_size(queue_size)?;

        let mut queue_dma = DmaRegionProvider::new();
        let queue_memory =
            QueueMemory::allocate(VIRTIO_BLOCK_QUEUE_INDEX, queue_size, &mut queue_dma)?;
        transport.program_queue(&queue_memory.config())?;
        transport.enable_queue(true)?;

        let config = transport.read_block_config();
        let block_size = if config.blk_size == 0 {
            DEFAULT_BLOCK_SIZE
        } else {
            config.blk_size
        };

        if block_size < VIRTIO_SECTOR_SIZE || block_size % VIRTIO_SECTOR_SIZE != 0 {
            return Err(fail_status(
                &mut transport,
                VirtioBlkError::UnsupportedBlockSize(block_size),
            ));
        }

        let mut device = Self {
            name,
            queue: QueueState::new(queue_size, queue_memory),
            transport,
            dma: DmaRegionProvider::new(),
            block_size,
            capacity_sectors: config.capacity,
            read_only: (device_features & FeatureBits::RO.bits()) != 0,
            flush_supported: (device_features & FeatureBits::FLUSH.bits()) != 0,
            queue_irq: None,
            irq_handler: None,
            irq_vector: None,
            #[cfg(test)]
            completion_hook: None,
        };

        if let Err(err) = device.init_interrupts() {
            return Err(fail_status(&mut device.transport, err));
        }

        status = status.with(DeviceStatus::DRIVER_OK);
        device.transport.set_status(status);

        Ok(device)
    }

    fn validate_buffer(&self, lba: u64, len: usize) -> Result<u64, VirtioBlkError> {
        if !len.is_multiple_of(self.block_size as usize) {
            return Err(VirtioBlkError::UnalignedBuffer);
        }
        let sectors_per_block = self.block_size as u64 / VIRTIO_SECTOR_SIZE as u64;
        let transfer_sectors = len as u64 / VIRTIO_SECTOR_SIZE as u64;
        let start_sector = lba
            .checked_mul(sectors_per_block)
            .ok_or(VirtioBlkError::AddressOverflow)?;
        let end = start_sector
            .checked_add(transfer_sectors)
            .ok_or(VirtioBlkError::AddressOverflow)?;
        if end > self.capacity_sectors {
            return Err(VirtioBlkError::OutOfRange);
        }
        Ok(start_sector)
    }

    fn io_read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), VirtioBlkError> {
        let sector = self.validate_buffer(lba, buffer.len())?;
        if VIRTIO_BLK_DEBUG {
            crate::println!(
                "[virtio-blk] read submit lba={} sectors={} len={}",
                lba,
                buffer.len() / self.block_size as usize,
                buffer.len()
            );
        }
        let mut request = RequestBuffers::new(&mut self.dma, buffer.len())?;
        request.write_header(RequestType::In, sector);
        let status = self
            .submit_request(&mut request, IoDirection::Read)
            .map_err(|err| {
                crate::println!(
                    "[virtio-blk] submit error {:?} lba={} len={}",
                    err,
                    sector,
                    buffer.len()
                );
                err
            })?;
        if status != 0 {
            crate::println!(
                "[virtio-blk] read error status=0x{status:02x} lba={sector} len={}",
                buffer.len()
            );
            return Err(VirtioBlkError::DeviceStatus(status));
        }
        if VIRTIO_BLK_DEBUG {
            crate::println!(
                "[virtio-blk] read complete lba={} sectors={} len={}",
                lba,
                buffer.len() / self.block_size as usize,
                buffer.len()
            );
        }
        request.copy_into(buffer);
        Ok(())
    }

    fn io_write(&mut self, lba: u64, buffer: &[u8]) -> Result<(), VirtioBlkError> {
        if self.read_only {
            return Err(VirtioBlkError::ReadOnly);
        }
        let sector = self.validate_buffer(lba, buffer.len())?;
        if VIRTIO_BLK_DEBUG {
            crate::println!(
                "[virtio-blk] write submit lba={} sectors={} len={}",
                lba,
                buffer.len() / self.block_size as usize,
                buffer.len()
            );
        }
        let mut request = RequestBuffers::new(&mut self.dma, buffer.len())?;
        request.write_header(RequestType::Out, sector);
        request.copy_from(buffer);
        let status = self.submit_request(&mut request, IoDirection::Write)?;
        if status != 0 {
            crate::println!(
                "[virtio-blk] write error status=0x{status:02x} lba={sector} len={}",
                buffer.len()
            );
            return Err(VirtioBlkError::DeviceStatus(status));
        }
        if VIRTIO_BLK_DEBUG {
            crate::println!(
                "[virtio-blk] write complete lba={} sectors={} len={}",
                lba,
                buffer.len() / self.block_size as usize,
                buffer.len()
            );
        }
        Ok(())
    }

    fn io_flush(&mut self) -> Result<(), VirtioBlkError> {
        if !self.flush_supported {
            return Err(VirtioBlkError::FlushUnsupported);
        }
        let mut request = RequestBuffers::new(&mut self.dma, 0)?;
        request.write_header(RequestType::Flush, 0);
        let status = self.submit_request(&mut request, IoDirection::None)?;
        if status != 0 {
            return Err(VirtioBlkError::DeviceStatus(status));
        }
        Ok(())
    }

    fn submit_request(
        &mut self,
        buffers: &mut RequestBuffers,
        direction: IoDirection,
    ) -> Result<u8, VirtioBlkError> {
        self.prepare_descriptors(buffers, direction);
        if let Some(irq) = self.queue_irq {
            irq.arm();
        }
        fence(Ordering::SeqCst);
        self.queue.push(0);
        fence(Ordering::SeqCst);
        if VIRTIO_BLK_DEBUG {
            crate::println!(
                "[virtio-blk] notify queue index={} len={}",
                VIRTIO_BLOCK_QUEUE_INDEX,
                buffers.data_len()
            );
        }
        self.transport
            .notify_queue(VIRTIO_BLOCK_QUEUE_INDEX)
            .map_err(VirtioBlkError::Transport)?;
        #[cfg(test)]
        if let Some(hook) = self.completion_hook {
            hook(&mut self.queue, buffers);
        }
        // Poll for completions to sidestep lost-interrupt issues seen under heavy load.
        let _completion = self.wait_for_used_with_timeout(buffers.data_len())?;
        if VIRTIO_BLK_DEBUG {
            crate::println!(
                "[virtio-blk] completion observed status=0x{:02x}",
                buffers.status()
            );
        }
        Ok(buffers.status())
    }

    fn wait_for_used_with_timeout(&mut self, data_len: usize) -> Result<UsedElem, VirtioBlkError> {
        const SPIN_LIMIT: usize = 5_000_000;
        let mut spins: usize = 0;
        loop {
            if let Some(entry) = self.queue.pop_used() {
                return Ok(entry);
            }
            spins = spins.wrapping_add(1);
            if VIRTIO_BLK_DEBUG && spins.is_multiple_of(1_000_000) {
                crate::println!(
                    "[virtio-blk] waiting for completion len={} spins={} used_idx={}",
                    data_len,
                    spins,
                    self.queue.used_idx
                );
            }
            if spins >= SPIN_LIMIT {
                crate::println!(
                    "[virtio-blk] completion timeout len={} spins={} used_idx={}",
                    data_len,
                    spins,
                    self.queue.used_idx
                );
                return Err(VirtioBlkError::Timeout);
            }
            core::hint::spin_loop();
        }
    }

    fn prepare_descriptors(&mut self, buffers: &RequestBuffers, direction: IoDirection) {
        let mut slices = self.queue.memory.slices();
        let desc = &mut slices.descriptors;
        let data_len = buffers.data_len();
        let status_index: u16 = if data_len > 0 { 2 } else { 1 };

        desc[0] = Descriptor {
            addr: buffers.header_phys().as_raw() as u64,
            len: core::mem::size_of::<VirtioBlkReqHeader>() as u32,
            flags: DescriptorFlags::NEXT.bits(),
            next: if data_len > 0 { 1 } else { status_index },
        };

        if data_len > 0 {
            let mut flags = DescriptorFlags::NEXT.bits();
            if matches!(direction, IoDirection::Read) {
                flags |= DescriptorFlags::WRITE.bits();
            }
            let data_phys = buffers
                .data_phys()
                .expect("data phys missing despite non-zero length");
            desc[1] = Descriptor {
                addr: data_phys.as_raw() as u64,
                len: data_len as u32,
                flags,
                next: 2,
            };
        }

        desc[status_index as usize] = Descriptor {
            addr: buffers.status_phys().as_raw() as u64,
            len: 1,
            flags: DescriptorFlags::WRITE.bits(),
            next: 0,
        };

        // Clear the unused descriptor slot when there is no payload.
        if data_len == 0 {
            desc[2] = Descriptor::default();
        }

        slices.avail.set_flags(0);
    }

    fn init_interrupts(&mut self) -> Result<(), VirtioBlkError> {
        if !self.transport.supports_queue_irq() {
            return Ok(());
        }

        let (queue_irq, handler) = allocate_queue_irq();
        let vector = INTERRUPTS
            .allocate_vector(handler)
            .map_err(VirtioBlkError::InterruptController)?;

        match self
            .transport
            .configure_queue_irq(VIRTIO_BLOCK_QUEUE_INDEX, vector)
        {
            Ok(()) => {
                queue_irq.arm();
                self.queue_irq = Some(queue_irq);
                self.irq_handler = Some(handler);
                self.irq_vector = Some(vector);
                Ok(())
            }
            Err(VirtioIrqError::Unsupported) => {
                let _ = INTERRUPTS.release_vector(vector, handler);
                Ok(())
            }
            Err(err) => {
                let _ = INTERRUPTS.release_vector(vector, handler);
                Err(VirtioBlkError::Interrupt(err))
            }
        }
    }

    fn wait_for_completion(&mut self, irq: &QueueInterrupt) -> UsedElem {
        loop {
            if let Some(entry) = self.queue.pop_used() {
                return entry;
            }
            // IRQs are still enabled, so a used entry will eventually become visible even if the
            // interrupt itself is lost. Busy-wait here to avoid blocking forever on `irq.wait()`.
            irq.wait_relaxed();
        }
    }

    #[cfg(test)]
    pub(self) fn set_completion_hook(&mut self, hook: fn(&mut QueueState, &mut RequestBuffers)) {
        self.completion_hook = Some(hook);
    }
}

impl<T: VirtioBlkTransport + VirtioIrqTransport> Device for VirtioBlkDevice<T> {
    fn name(&self) -> &str {
        &self.name
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Block
    }
}

impl<T: VirtioBlkTransport + VirtioIrqTransport> BlockDevice for VirtioBlkDevice<T> {
    type Error = VirtioBlkError;

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn num_blocks(&self) -> u64 {
        (self.capacity_sectors * VIRTIO_SECTOR_SIZE as u64) / self.block_size as u64
    }

    fn is_read_only(&self) -> bool {
        self.read_only
    }

    fn read_blocks(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
        self.io_read(lba, buffer)
    }

    fn write_blocks(&mut self, lba: u64, buffer: &[u8]) -> Result<(), Self::Error> {
        self.io_write(lba, buffer)
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        self.io_flush()
    }
}

fn select_features(device_features: u32) -> u32 {
    let supported =
        FeatureBits::RO.bits() | FeatureBits::FLUSH.bits() | FeatureBits::BLK_SIZE.bits();
    device_features & supported
}

bitflags::bitflags! {
    struct FeatureBits: u32 {
        const SIZE_MAX = 1 << 0;
        const SEG_MAX = 1 << 1;
        const GEOMETRY = 1 << 4;
        const RO = 1 << 5;
        const BLK_SIZE = 1 << 6;
        const FLUSH = 1 << 9;
        const TOPOLOGY = 1 << 10;
        const CONFIG_WCE = 1 << 11;
        const DISCARD = 1 << 13;
        const WRITE_ZEROES = 1 << 14;
    }
}

#[derive(Debug)]
pub enum VirtioBlkError {
    Transport(TransportError),
    Queue(QueueError),
    Dma(DmaError),
    FeatureNegotiationFailed,
    QueueTooSmall(u16),
    UnsupportedBlockSize(u32),
    UnalignedBuffer,
    AddressOverflow,
    OutOfRange,
    DeviceStatus(u8),
    ReadOnly,
    FlushUnsupported,
    Interrupt(VirtioIrqError),
    InterruptController(InterruptError),
    Timeout,
}

impl From<TransportError> for VirtioBlkError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<QueueError> for VirtioBlkError {
    fn from(value: QueueError) -> Self {
        Self::Queue(value)
    }
}

impl From<DmaError> for VirtioBlkError {
    fn from(value: DmaError) -> Self {
        Self::Dma(value)
    }
}

impl From<VirtioIrqError> for VirtioBlkError {
    fn from(value: VirtioIrqError) -> Self {
        Self::Interrupt(value)
    }
}

struct QueueState {
    size: u16,
    memory: QueueMemory,
    avail_idx: u16,
    used_idx: u16,
}

impl QueueState {
    fn new(size: u16, memory: QueueMemory) -> Self {
        Self {
            size,
            memory,
            avail_idx: 0,
            used_idx: 0,
        }
    }

    fn push(&mut self, head: u16) {
        let mut slices = self.memory.slices();
        let slot = (self.avail_idx % self.size) as usize;
        slices.avail.ring()[slot] = head;
        self.avail_idx = self.avail_idx.wrapping_add(1);
        slices.avail.set_idx(self.avail_idx);
    }

    fn wait_for_used(&mut self) -> UsedElem {
        loop {
            if let Some(entry) = self.pop_used() {
                return entry;
            }
            core::hint::spin_loop();
        }
    }

    fn pop_used(&mut self) -> Option<UsedElem> {
        let mut slices = self.memory.slices();
        let device_used = slices.used.idx();
        if device_used == self.used_idx {
            return None;
        }

        let slot = (self.used_idx % self.size) as usize;
        let ring = slices.used.ring();
        let entry = unsafe { core::ptr::read_volatile(&ring[slot]) };
        self.used_idx = self.used_idx.wrapping_add(1);
        Some(entry)
    }
}

fn allocate_queue_irq() -> (&'static QueueInterrupt, &'static QueueInterruptHandler) {
    let queue = Box::leak(Box::new(QueueInterrupt::new()));
    let handler = Box::leak(Box::new(QueueInterruptHandler::new(queue)));
    (queue, handler)
}

struct QueueInterrupt {
    pending: AtomicBool,
}

impl QueueInterrupt {
    const fn new() -> Self {
        Self {
            pending: AtomicBool::new(false),
        }
    }

    fn arm(&self) {
        self.pending.store(false, Ordering::Release);
    }

    fn wait(&self) {
        loop {
            if self.pending.swap(false, Ordering::AcqRel) {
                break;
            }
            core::hint::spin_loop();
        }
    }

    /// Polls the pending flag once; intended for busy-wait loops where interrupts may be lost.
    fn wait_relaxed(&self) {
        let _ = self.pending.swap(false, Ordering::AcqRel);
        core::hint::spin_loop();
    }

    fn notify(&self) {
        self.pending.store(true, Ordering::Release);
    }
}

struct QueueInterruptHandler {
    queue: &'static QueueInterrupt,
}

impl QueueInterruptHandler {
    const fn new(queue: &'static QueueInterrupt) -> Self {
        Self { queue }
    }
}

impl InterruptServiceRoutine for QueueInterruptHandler {
    fn handle(&self, _info: TrapInfo, _frame: &mut CurrentTrapFrame) {
        self.queue.notify();
    }
}

#[cfg(test)]
impl QueueState {
    fn test_complete(&mut self, len: u32) {
        let mut slices = self.memory.slices();
        let slot = (self.used_idx % self.size) as usize;
        let ring = slices.used.ring();
        unsafe {
            core::ptr::write_volatile(&mut ring[slot], UsedElem { id: 0, len });
        }
        let next = self.used_idx.wrapping_add(1);
        slices.used.set_idx(next);
    }
}

enum IoDirection {
    Read,
    Write,
    None,
}

#[repr(u32)]
enum RequestType {
    In = 0,
    Out = 1,
    Flush = 4,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioBlkReqHeader {
    ty: u32,
    reserved: u32,
    sector: u64,
}

struct RequestBuffers {
    region: DmaRegion,
    header_offset: usize,
    data_offset: usize,
    data_len: usize,
    status_offset: usize,
}

impl RequestBuffers {
    fn new(provider: &mut DmaRegionProvider, data_len: usize) -> Result<Self, DmaError> {
        let header_size = core::mem::size_of::<VirtioBlkReqHeader>();
        let status_size = 1;
        let total = header_size + data_len + status_size;
        let page_bytes = PageSize::SIZE_4K.bytes();
        let size = align_up(total, page_bytes);
        let mut region = provider.allocate(size, page_bytes)?;
        region.as_bytes_mut().fill(0);
        let status_offset = header_size + data_len;
        let this = Self {
            region,
            header_offset: 0,
            data_offset: header_size,
            data_len,
            status_offset,
        };
        let mut this = this;
        unsafe { core::ptr::write_volatile(this.status_ptr(), 0xFF) };
        Ok(this)
    }

    fn header_phys(&self) -> PhysAddr {
        self.region.phys_base()
    }

    fn data_phys(&self) -> Option<PhysAddr> {
        if self.data_len == 0 {
            None
        } else {
            self.region.phys_base().checked_add(self.data_offset)
        }
    }

    fn status_phys(&self) -> PhysAddr {
        self.region
            .phys_base()
            .checked_add(self.status_offset)
            .expect("status address overflow")
    }

    fn data_len(&self) -> usize {
        self.data_len
    }

    fn header_ptr(&self) -> *mut VirtioBlkReqHeader {
        self.region
            .virt_base()
            .checked_add(self.header_offset)
            .expect("header virt overflow")
            .into_mut_ptr() as *mut VirtioBlkReqHeader
    }

    fn data_mut(&mut self) -> Option<&mut [u8]> {
        if self.data_len == 0 {
            None
        } else {
            let virt = self
                .region
                .virt_base()
                .checked_add(self.data_offset)
                .expect("data virt overflow");
            unsafe {
                Some(core::slice::from_raw_parts_mut(
                    virt.into_mut_ptr(),
                    self.data_len,
                ))
            }
        }
    }

    fn data(&self) -> Option<&[u8]> {
        if self.data_len == 0 {
            None
        } else {
            let virt = self
                .region
                .virt_base()
                .checked_add(self.data_offset)
                .expect("data virt overflow");
            unsafe { Some(core::slice::from_raw_parts(virt.into_ptr(), self.data_len)) }
        }
    }

    fn status_ptr(&self) -> *mut u8 {
        self.region
            .virt_base()
            .checked_add(self.status_offset)
            .expect("status virt overflow")
            .into_mut_ptr()
    }

    fn write_header(&mut self, ty: RequestType, sector: u64) {
        let header = VirtioBlkReqHeader {
            ty: ty as u32,
            reserved: 0,
            sector,
        };
        unsafe {
            core::ptr::write_volatile(self.header_ptr(), header);
        }
        self.set_status(0);
    }

    fn copy_into(&self, buffer: &mut [u8]) {
        if self.data_len == 0 {
            debug_assert!(buffer.is_empty());
            return;
        }
        if let Some(data) = self.data() {
            debug_assert_eq!(data.len(), buffer.len());
            buffer.copy_from_slice(data);
        }
    }

    fn copy_from(&mut self, buffer: &[u8]) {
        if self.data_len == 0 {
            debug_assert!(buffer.is_empty());
            return;
        }
        if let Some(data) = self.data_mut() {
            debug_assert_eq!(data.len(), buffer.len());
            data.copy_from_slice(buffer);
        }
    }

    fn status(&self) -> u8 {
        unsafe { core::ptr::read_volatile(self.status_ptr()) }
    }

    fn set_status(&mut self, value: u8) {
        unsafe { core::ptr::write_volatile(self.status_ptr(), value) }
    }
}

fn align_up(value: usize, align: usize) -> usize {
    if align == 0 {
        return value;
    }
    let mask = align - 1;
    value.checked_add(mask).expect("alignment overflow") & !mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::Cell;
    use core::sync::atomic::{AtomicU8, Ordering};

    use crate::device::virtio::queue::QueueConfig;
    use crate::device::virtio::transport::QueueNotifier;
    use crate::println;
    use crate::test::kernel_test_case;

    const fn write_capture_init() -> SpinLock<Vec<u8>> {
        SpinLock::new(Vec::new())
    }

    static READ_PATTERN: AtomicU8 = AtomicU8::new(0x5Au8);
    static WRITE_CAPTURE: LazyLock<SpinLock<Vec<u8>>> = LazyLock::new_const(write_capture_init);

    #[kernel_test_case]
    fn queue_waits_for_completion() {
        println!("[test] queue_waits_for_completion");

        let mut provider = DmaRegionProvider::new();
        let queue_mem = QueueMemory::allocate(0, 8, &mut provider).expect("queue allocation");
        let mut queue = QueueState::new(8, queue_mem);
        queue.push(0);
        queue.test_complete(0);
        let _ = queue.wait_for_used();
    }

    #[kernel_test_case]
    fn request_buffers_copy_roundtrip() {
        println!("[test] request_buffers_copy_roundtrip");

        let mut provider = DmaRegionProvider::new();
        let mut buffers = RequestBuffers::new(&mut provider, 512).expect("dma alloc");
        let payload = [0xA5u8; 512];
        buffers.copy_from(&payload);
        let mut out = [0u8; 512];
        buffers.copy_into(&mut out);
        assert_eq!(payload, out);
    }

    #[kernel_test_case]
    fn virtio_blk_read_roundtrip() {
        println!("[test] virtio_blk_read_roundtrip");

        let transport = MockTransport::default();
        let mut device = VirtioBlkDevice::new("testblk".into(), transport).expect("device init");
        device.set_completion_hook(complete_read);
        let mut buffer = [0u8; 512];
        device.read_blocks(0, &mut buffer).expect("read");
        let expected = READ_PATTERN.load(Ordering::Relaxed);
        assert!(buffer.iter().all(|byte| *byte == expected));
    }

    #[kernel_test_case]
    fn virtio_blk_write_captures_data() {
        println!("[test] virtio_blk_write_captures_data");

        let transport = MockTransport::default();
        let mut device = VirtioBlkDevice::new("testblk".into(), transport).expect("device init");
        device.set_completion_hook(complete_write);
        let buffer = [0x3Cu8; 512];
        device.write_blocks(0, &buffer).expect("write");
        let capture = WRITE_CAPTURE.lock();
        assert_eq!(capture.as_slice(), buffer);
    }

    /// Validates virtio-blk against the QEMU-provided disk image.
    ///
    /// # Implicit dependency
    /// Relies on `xtask::prepare_test_block_image` attaching `target/virtio-blk-test.img`
    /// as the first VirtIO block device during `cargo xtask test` runs. The image seeds
    /// sector 0 with the repeated pattern `CYRIUSBLKTESTIMG` and reserves sector 1 for
    /// writeback verification.
    #[kernel_test_case]
    fn virtio_blk_rw_roundtrip_integration() {
        println!("[test] virtio_blk_rw_roundtrip_integration");

        const PATTERN: &[u8] = b"CYRIUSBLKTESTIMG";
        const READ_LBA: u64 = 0;
        const WRITE_LBA: u64 = 1;

        with_devices(|devices| {
            assert!(
                !devices.is_empty(),
                "virtio-blk integration test requires a block device"
            );
            let mut device = devices[0].lock();

            let block_size = device.block_size() as usize;
            let mut read_buf = vec![0u8; block_size];
            device
                .read_blocks(READ_LBA, &mut read_buf)
                .expect("read seed block");

            for (index, byte) in read_buf.iter().enumerate().take(PATTERN.len()) {
                assert_eq!(
                    *byte,
                    PATTERN[index % PATTERN.len()],
                    "seed pattern mismatch at byte {index}"
                );
            }

            let write_buf = vec![0xA5u8; block_size];
            device
                .write_blocks(WRITE_LBA, &write_buf)
                .expect("write payload");

            match device.flush() {
                Ok(()) => {}
                Err(VirtioBlkError::FlushUnsupported) => {}
                Err(err) => panic!("flush failed: {err:?}"),
            }

            let mut verify_buf = vec![0u8; block_size];
            device
                .read_blocks(WRITE_LBA, &mut verify_buf)
                .expect("read back payload");
            assert_eq!(verify_buf, write_buf, "written block mismatch");
        });
    }

    fn complete_read(queue: &mut QueueState, buffers: &mut RequestBuffers) {
        if let Some(data) = buffers.data_mut() {
            data.fill(READ_PATTERN.load(Ordering::Relaxed));
        }
        buffers.set_status(0);
        let len = buffers.data_len().min(u32::MAX as usize) as u32;
        queue.test_complete(len);
    }

    fn complete_write(queue: &mut QueueState, buffers: &mut RequestBuffers) {
        if let Some(data) = buffers.data() {
            let mut guard = WRITE_CAPTURE.lock();
            guard.clear();
            guard.extend_from_slice(data);
        }
        buffers.set_status(0);
        let len = buffers.data_len().min(u32::MAX as usize) as u32;
        queue.test_complete(len);
    }

    #[derive(Clone)]
    struct MockTransport {
        status: Cell<DeviceStatus>,
        device_features: u32,
        driver_features: Cell<u32>,
        queue_size: Cell<u16>,
        selected_queue: Cell<u16>,
        config: VirtioBlkConfig,
    }

    impl Default for MockTransport {
        fn default() -> Self {
            Self {
                status: Cell::new(DeviceStatus::empty()),
                device_features: FeatureBits::FLUSH.bits() | FeatureBits::BLK_SIZE.bits(),
                driver_features: Cell::new(0),
                queue_size: Cell::new(8),
                selected_queue: Cell::new(0),
                config: VirtioBlkConfig {
                    capacity: 2048,
                    blk_size: DEFAULT_BLOCK_SIZE,
                    ..Default::default()
                },
            }
        }
    }

    impl Transport for MockTransport {
        fn device_id(&self) -> u16 {
            0x1042
        }

        fn read_device_features(&self, _select: u32) -> u32 {
            self.device_features
        }

        fn write_driver_features(&self, _select: u32, value: u32) {
            self.driver_features.set(value);
        }

        fn num_queues(&self) -> u16 {
            1
        }

        fn status(&self) -> DeviceStatus {
            self.status.get()
        }

        fn set_status(&self, status: DeviceStatus) {
            self.status.set(status);
        }

        fn config_generation(&self) -> u8 {
            0
        }

        fn select_queue(&self, queue_index: u16) -> Result<(), TransportError> {
            self.selected_queue.set(queue_index);
            Ok(())
        }

        fn queue_size(&self) -> Result<u16, TransportError> {
            Ok(self.queue_size.get())
        }

        fn set_queue_size(&self, size: u16) -> Result<(), TransportError> {
            self.queue_size.set(size);
            Ok(())
        }

        fn program_queue(&self, _cfg: &QueueConfig) -> Result<(), TransportError> {
            Ok(())
        }

        fn enable_queue(&self, _enabled: bool) -> Result<(), TransportError> {
            Ok(())
        }
    }

    impl VirtioIrqTransport for MockTransport {}

    impl QueueNotifier for MockTransport {
        fn notify_queue(&self, queue_index: u16) -> Result<(), TransportError> {
            if queue_index != self.selected_queue.get() {
                return Err(TransportError::QueueUnavailable);
            }
            Ok(())
        }
    }

    impl VirtioBlkTransport for MockTransport {
        fn read_block_config(&self) -> VirtioBlkConfig {
            self.config
        }
    }
}
