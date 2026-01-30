use alloc::{boxed::Box, format, string::String, sync::Arc, vec::Vec};

use crate::device::net::{LinkState, NetworkDevice, NetworkDeviceProvider};
use crate::device::virtio::pci::{self, VirtioPciTransport};
use crate::device::virtio::queue::{
    Descriptor, DescriptorFlags, QueueError, QueueMemory, UsedElem,
};
use crate::device::virtio::transport::{
    DeviceStatus, Transport, TransportError, VirtioIrqError, VirtioIrqTransport,
};
use crate::device::{Device, DeviceType};
use crate::interrupt::{INTERRUPTS, InterruptError, InterruptServiceRoutine};
use crate::mem::addr::{Addr, PageSize, PhysAddr, VirtIntoPtr, align_up};
use crate::mem::dma::{DmaError, DmaRegion, DmaRegionProvider};
use crate::trap::{CurrentTrapFrame, TrapInfo};
use crate::util::lazylock::LazyLock;
use crate::util::spinlock::SpinLock;

use core::sync::atomic::fence;
use core::sync::atomic::{AtomicBool, Ordering};

const VIRTIO_NET_RX_QUEUE_INDEX: u16 = 0;
const VIRTIO_NET_TX_QUEUE_INDEX: u16 = 1;
const MAX_QUEUE_SIZE: u16 = 256;
const MIN_QUEUE_SIZE: u16 = 2;
// NOTE: We currently assume one packet maps to exactly two descriptors:
//       header + payload. This is a deliberate simplification and MUST be
//       revisited before enabling features such as merged RX buffers, GSO,
//       or any multi-segment TX/RX path.
const DESCRIPTOR_STRIDE: u16 = 2;
const DEFAULT_MTU: usize = 1500;
const ETHERNET_HEADER_LEN: usize = 14;
const MAX_FRAME_SIZE: usize = 2048;

const fn net_registry_init() -> SpinLock<Vec<Arc<SpinLock<VirtioPciNetDevice>>>> {
    SpinLock::new(Vec::new())
}

static NET_DEVICES: LazyLock<SpinLock<Vec<Arc<SpinLock<VirtioPciNetDevice>>>>> =
    LazyLock::new_const(net_registry_init);

fn fail_status<T: Transport>(transport: &mut T, err: VirtioNetError) -> VirtioNetError {
    transport.set_status(DeviceStatus::FAILED);
    err
}

pub type VirtioPciNetDevice = VirtioNetDevice<VirtioPciTransport>;

pub struct VirtioNetProvider;

impl NetworkDeviceProvider for VirtioNetProvider {
    type Device = VirtioPciNetDevice;

    fn probe(&self) -> usize {
        probe_pci_devices()
    }

    fn with_devices<R>(&self, f: impl FnOnce(&[Arc<SpinLock<Self::Device>>]) -> R) -> R {
        with_devices(f)
    }
}

pub fn probe_pci_devices() -> usize {
    let transports = pci::enumerate_net_transports();
    let mut guard = NET_DEVICES.get().lock();
    let existing = guard.len();
    let mut added = 0;

    for transport in transports {
        let name = format!("virtio-net{}", existing + added);
        match VirtioNetDevice::new(name, transport) {
            Ok(device) => {
                guard.push(Arc::new(SpinLock::new(device)));
                added += 1;
            }
            Err(err) => {
                crate::println!("[net] failed to initialise virtio device: {err:?}");
            }
        }
    }

    added
}

pub fn with_devices<R>(f: impl FnOnce(&[Arc<SpinLock<VirtioPciNetDevice>>]) -> R) -> R {
    let guard = NET_DEVICES.get().lock();
    let devices = guard.clone();
    drop(guard);
    f(devices.as_slice())
}

pub trait VirtioNetTransport: Transport {
    fn config_len(&self) -> usize;
    fn read_config_bytes(&self, offset: usize, out: &mut [u8]) -> Result<(), TransportError>;
}

impl VirtioNetTransport for VirtioPciTransport {
    fn config_len(&self) -> usize {
        self.device_config().len()
    }

    fn read_config_bytes(&self, offset: usize, out: &mut [u8]) -> Result<(), TransportError> {
        let cfg = self.device_config();
        let end = offset
            .checked_add(out.len())
            .ok_or(TransportError::NotifyUnavailable)?;
        if end > cfg.len() {
            return Err(TransportError::NotifyUnavailable);
        }
        unsafe {
            let base = cfg.as_ptr().add(offset);
            for (index, byte) in out.iter_mut().enumerate() {
                *byte = core::ptr::read_volatile(base.add(index));
            }
        }
        Ok(())
    }
}

pub struct VirtioNetDevice<T: VirtioNetTransport> {
    name: String,
    transport: T,
    rx_queue: QueueState,
    tx_queue: QueueState,
    rx_buffers: Vec<NetBuffer>,
    tx_buffer: NetBuffer,
    tx_free: Vec<u16>,
    _dma: DmaRegionProvider,
    mac: [u8; 6],
    mtu: usize,
    link_state: LinkState,
    queue_irq: Option<&'static QueueInterrupt>,
    irq_handler: Option<&'static QueueInterruptHandler>,
    irq_vector: Option<u8>,
    #[cfg(test)]
    completion_hook: Option<fn(&mut QueueState, u16)>,
}

impl<T: VirtioNetTransport + VirtioIrqTransport> VirtioNetDevice<T> {
    pub fn new(name: String, mut transport: T) -> Result<Self, VirtioNetError> {
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
                VirtioNetError::FeatureNegotiationFailed,
            ));
        }

        let num_queues = transport.num_queues();
        if num_queues < 2 {
            return Err(fail_status(
                &mut transport,
                VirtioNetError::InsufficientQueues(num_queues),
            ));
        }

        let mut queue_dma = DmaRegionProvider::new();
        let mut rx_queue = setup_queue(&mut transport, VIRTIO_NET_RX_QUEUE_INDEX, &mut queue_dma)?;
        let tx_queue = setup_queue(&mut transport, VIRTIO_NET_TX_QUEUE_INDEX, &mut queue_dma)?;

        let (mac, link_state) = read_config(&transport, driver_features)?;
        let mtu = DEFAULT_MTU;
        let frame_capacity = compute_frame_capacity(mtu)?;

        let mut dma = DmaRegionProvider::new();
        let mut rx_buffers = Vec::with_capacity(rx_queue.head_capacity() as usize);
        for buffer_index in 0..rx_queue.head_capacity() {
            let head = buffer_index * DESCRIPTOR_STRIDE;
            let buffer = NetBuffer::new(&mut dma, frame_capacity)?;
            write_rx_descriptors(&mut rx_queue, head, &buffer);
            rx_queue.push(head)?;
            rx_buffers.push(buffer);
        }
        {
            let mut slices = rx_queue.memory.slices();
            slices.avail.set_flags(0);
        }

        let tx_buffer = NetBuffer::new(&mut dma, frame_capacity)?;
        let tx_free = (0..tx_queue.head_capacity())
            .map(|idx| idx * DESCRIPTOR_STRIDE)
            .collect();

        let mut device = Self {
            name,
            transport,
            rx_queue,
            tx_queue,
            rx_buffers,
            tx_buffer,
            tx_free,
            _dma: dma,
            mac,
            mtu,
            link_state,
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

    fn init_interrupts(&mut self) -> Result<(), VirtioNetError> {
        if !self.transport.supports_queue_irq() {
            return Ok(());
        }

        let (queue_irq, handler) = allocate_queue_irq();
        let vector = INTERRUPTS
            .allocate_vector(handler)
            .map_err(VirtioNetError::InterruptController)?;

        match self
            .transport
            .configure_queue_irq(VIRTIO_NET_RX_QUEUE_INDEX, vector)
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
                Err(VirtioNetError::Interrupt(err))
            }
        }
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), VirtioNetError> {
        let head = self.allocate_tx_head()?;
        self.tx_buffer.prepare_tx(frame)?;
        self.prepare_tx_descriptor(head, frame.len());
        if let Some(irq) = self.queue_irq {
            irq.arm();
        }
        self.tx_queue.push(head)?;
        self.transport
            .notify_queue(VIRTIO_NET_TX_QUEUE_INDEX)
            .map_err(VirtioNetError::Transport)?;
        #[cfg(test)]
        if let Some(hook) = self.completion_hook {
            hook(&mut self.tx_queue, head);
        }
        // NOTE: TX is currently synchronous (one outstanding completion
        // awaited here). This assumes single-packet semantics; do not
        // introduce pipelining without switching to full reclaim logic.
        let completion = self.tx_queue.wait_for_used();
        self.release_tx_head(completion.id as u16);
        Ok(())
    }

    fn prepare_tx_descriptor(&mut self, head: u16, frame_len: usize) {
        let header_len = self.tx_buffer.header_len();
        let total_len = self
            .tx_buffer
            .total_len_for_payload(frame_len)
            .min(u32::MAX as usize) as u32;
        let mut slices = self.tx_queue.memory.slices();
        let head_index = head as usize;
        let data_index = head_index + 1;
        slices.descriptors[head_index] = Descriptor {
            addr: self.tx_buffer.header_phys().as_raw() as u64,
            len: header_len as u32,
            flags: DescriptorFlags::NEXT.bits(),
            next: head + 1,
        };
        slices.descriptors[data_index] = Descriptor {
            addr: self
                .tx_buffer
                .data_phys()
                .expect("tx data phys missing")
                .as_raw() as u64,
            len: total_len.saturating_sub(header_len as u32),
            flags: 0,
            next: 0,
        };
        slices.avail.set_flags(0);
    }

    fn poll_receive(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, VirtioNetError> {
        let Some(used) = self.rx_queue.pop_used() else {
            return Ok(None);
        };
        let index = used.id as usize;
        if !index.is_multiple_of(DESCRIPTOR_STRIDE as usize) {
            return Err(VirtioNetError::InvalidRxDescriptor(index));
        }
        let buffer_index = index / DESCRIPTOR_STRIDE as usize;
        if buffer_index >= self.rx_buffers.len() {
            return Err(VirtioNetError::InvalidRxDescriptor(index));
        }
        let header_len = self.rx_buffers[buffer_index].header_len();
        let total = used.len as usize;
        if total < header_len {
            return Err(VirtioNetError::ShortRx(total));
        }
        // NOTE: RX currently assumes one buffer holds one full packet.
        // Multi-buffer packets (e.g. merged RX buffers) are not supported yet.
        let payload_len = total - header_len;
        let capacity = self.rx_buffers[buffer_index].data_len();
        if payload_len > capacity {
            return Err(VirtioNetError::RxOverflow {
                capacity,
                received: payload_len,
            });
        }
        if payload_len > buffer.len() {
            return Err(VirtioNetError::BufferTooSmall {
                needed: payload_len,
                provided: buffer.len(),
            });
        }
        let data = self.rx_buffers[buffer_index].data();
        buffer[..payload_len].copy_from_slice(&data[..payload_len]);
        write_rx_descriptors(
            &mut self.rx_queue,
            index as u16,
            &self.rx_buffers[buffer_index],
        );
        self.rx_queue.push(index as u16)?;
        Ok(Some(payload_len))
    }

    fn allocate_tx_head(&mut self) -> Result<u16, VirtioNetError> {
        self.reclaim_tx_used();
        self.tx_free.pop().ok_or(VirtioNetError::TxBusy)
    }

    fn release_tx_head(&mut self, head: u16) {
        if head.is_multiple_of(DESCRIPTOR_STRIDE) {
            self.tx_free.push(head);
        }
    }

    fn reclaim_tx_used(&mut self) {
        while let Some(entry) = self.tx_queue.pop_used() {
            self.release_tx_head(entry.id as u16);
        }
    }

    #[cfg(test)]
    pub(self) fn set_completion_hook(&mut self, hook: fn(&mut QueueState, u16)) {
        self.completion_hook = Some(hook);
    }

    #[cfg(test)]
    fn test_transmit_with_timeout(
        &mut self,
        frame: &[u8],
        spins: usize,
    ) -> Result<(), VirtioNetError> {
        let head = self.allocate_tx_head()?;
        self.tx_buffer.prepare_tx(frame)?;
        self.prepare_tx_descriptor(head, frame.len());
        if let Some(irq) = self.queue_irq {
            irq.arm();
        }
        self.tx_queue.push(head)?;
        self.transport
            .notify_queue(VIRTIO_NET_TX_QUEUE_INDEX)
            .map_err(VirtioNetError::Transport)?;
        #[cfg(test)]
        if let Some(hook) = self.completion_hook {
            hook(&mut self.tx_queue, head);
        }
        for _ in 0..spins {
            if self.tx_queue.pop_used().is_some() {
                self.release_tx_head(head);
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(VirtioNetError::TxTimeout)
    }
}

impl<T: VirtioNetTransport + VirtioIrqTransport> Device for VirtioNetDevice<T> {
    fn name(&self) -> &str {
        &self.name
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Network
    }
}

impl<T: VirtioNetTransport + VirtioIrqTransport> NetworkDevice for VirtioNetDevice<T> {
    type Error = VirtioNetError;

    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    fn link_state(&self) -> LinkState {
        self.link_state
    }

    fn transmit_frame(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        self.transmit(frame)
    }

    fn receive_frame(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        self.poll_receive(buffer)
    }
}

fn setup_queue<T: VirtioNetTransport>(
    transport: &mut T,
    index: u16,
    dma: &mut DmaRegionProvider,
) -> Result<QueueState, VirtioNetError> {
    transport.select_queue(index)?;
    let device_queue_size = transport.queue_size()?;
    if device_queue_size < MIN_QUEUE_SIZE {
        return Err(VirtioNetError::QueueTooSmall(device_queue_size));
    }
    let queue_size = device_queue_size.min(MAX_QUEUE_SIZE);
    if queue_size % DESCRIPTOR_STRIDE != 0 {
        return Err(VirtioNetError::QueueNotEven(queue_size));
    }
    transport.set_queue_size(queue_size)?;

    let queue_memory = QueueMemory::allocate(index, queue_size, dma)?;
    transport.program_queue(&queue_memory.config())?;
    transport.enable_queue(true)?;

    Ok(QueueState::new(queue_size, queue_memory))
}

fn compute_frame_capacity(mtu: usize) -> Result<usize, VirtioNetError> {
    let frame = mtu
        .checked_add(ETHERNET_HEADER_LEN)
        .ok_or(VirtioNetError::FrameTooLarge(usize::MAX))?;
    if frame > MAX_FRAME_SIZE {
        return Err(VirtioNetError::FrameTooLarge(frame));
    }
    Ok(frame)
}

fn select_features(device_features: u32) -> u32 {
    let supported = FeatureBits::MAC.bits() | FeatureBits::STATUS.bits();
    device_features & supported
}

fn read_config<T: VirtioNetTransport>(
    transport: &T,
    features: u32,
) -> Result<([u8; 6], LinkState), VirtioNetError> {
    let layout = NetConfigLayout::new(features);
    let mut mac = [0u8; 6];
    if let Some(offset) = layout.mac_offset {
        read_config_bytes(transport, offset, &mut mac)?;
    }
    let link_state = if let Some(offset) = layout.status_offset {
        let status = read_config_u16(transport, offset)?;
        if status & NetStatus::LINK_UP.bits() != 0 {
            LinkState::Up
        } else {
            LinkState::Down
        }
    } else {
        LinkState::Unknown
    };
    Ok((mac, link_state))
}

fn read_config_bytes<T: VirtioNetTransport>(
    transport: &T,
    offset: usize,
    out: &mut [u8],
) -> Result<(), VirtioNetError> {
    let end = offset
        .checked_add(out.len())
        .ok_or(VirtioNetError::ConfigTooSmall {
            required: offset,
            actual: transport.config_len(),
        })?;
    if end > transport.config_len() {
        return Err(VirtioNetError::ConfigTooSmall {
            required: end,
            actual: transport.config_len(),
        });
    }
    transport
        .read_config_bytes(offset, out)
        .map_err(VirtioNetError::Transport)?;
    Ok(())
}

fn read_config_u16<T: VirtioNetTransport>(
    transport: &T,
    offset: usize,
) -> Result<u16, VirtioNetError> {
    let mut bytes = [0u8; 2];
    read_config_bytes(transport, offset, &mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

bitflags::bitflags! {
    struct FeatureBits: u32 {
        const MAC = 1 << 5;
        const STATUS = 1 << 16;
    }
}

bitflags::bitflags! {
    struct NetStatus: u16 {
        const LINK_UP = 1;
    }
}

struct NetConfigLayout {
    mac_offset: Option<usize>,
    status_offset: Option<usize>,
}

impl NetConfigLayout {
    fn new(features: u32) -> Self {
        // NOTE: Manual offset math assumes the current minimal config layout.
        // When more config fields/features are supported, replace this with a
        // structured parser tied to the virtio-net spec layout.
        let mut offset = 0;
        let mac_offset = if features & FeatureBits::MAC.bits() != 0 {
            let current = offset;
            offset += 6;
            Some(current)
        } else {
            None
        };
        let status_offset = if features & FeatureBits::STATUS.bits() != 0 {
            Some(offset)
        } else {
            None
        };
        Self {
            mac_offset,
            status_offset,
        }
    }
}

#[derive(Debug)]
pub enum VirtioNetError {
    Transport(TransportError),
    Queue(QueueError),
    Dma(DmaError),
    FeatureNegotiationFailed,
    InsufficientQueues(u16),
    QueueTooSmall(u16),
    QueueNotEven(u16),
    ConfigTooSmall { required: usize, actual: usize },
    FrameTooLarge(usize),
    BufferTooSmall { needed: usize, provided: usize },
    RxOverflow { capacity: usize, received: usize },
    InvalidRxDescriptor(usize),
    ShortRx(usize),
    TxBusy,
    TxTimeout,
    Interrupt(VirtioIrqError),
    InterruptController(InterruptError),
}

impl From<TransportError> for VirtioNetError {
    fn from(value: TransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<QueueError> for VirtioNetError {
    fn from(value: QueueError) -> Self {
        Self::Queue(value)
    }
}

impl From<DmaError> for VirtioNetError {
    fn from(value: DmaError) -> Self {
        Self::Dma(value)
    }
}

impl From<VirtioIrqError> for VirtioNetError {
    fn from(value: VirtioIrqError) -> Self {
        Self::Interrupt(value)
    }
}

struct QueueState {
    size: u16,
    memory: QueueMemory,
    avail_idx: u16,
    used_idx: u16,
    in_flight: u16,
    head_stride: u16,
    head_capacity: u16,
}

impl QueueState {
    fn new(size: u16, memory: QueueMemory) -> Self {
        let head_stride = DESCRIPTOR_STRIDE;
        let head_capacity = size / head_stride;
        Self {
            size,
            memory,
            avail_idx: 0,
            used_idx: 0,
            in_flight: 0,
            head_stride,
            head_capacity,
        }
    }

    fn head_capacity(&self) -> u16 {
        self.head_capacity
    }

    fn push(&mut self, head: u16) -> Result<(), QueueError> {
        if self.in_flight >= self.head_capacity {
            return Err(QueueError::QueueFull);
        }
        debug_assert_eq!(head % self.head_stride, 0);
        let mut slices = self.memory.slices();
        let slot = (self.avail_idx % self.size) as usize;
        slices.avail.ring()[slot] = head;
        // Ensure descriptor writes are visible before updating avail.idx.
        fence(Ordering::Release);
        self.avail_idx = self.avail_idx.wrapping_add(1);
        slices.avail.set_idx(self.avail_idx);
        self.in_flight = self.in_flight.wrapping_add(1);
        Ok(())
    }

    fn wait_for_used(&mut self) -> UsedElem {
        // Polling-only completion for now; IRQs are not wired into the wait path.
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

        // Ensure we observe the used ring entry after reading used.idx.
        fence(Ordering::Acquire);
        let slot = (self.used_idx % self.size) as usize;
        let ring = slices.used.ring();
        let entry = unsafe { core::ptr::read_volatile(&ring[slot]) };
        self.used_idx = self.used_idx.wrapping_add(1);
        self.in_flight = self.in_flight.saturating_sub(1);
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

    fn notify(&self) {
        // NOTE: IRQs are currently not integrated into the wait path.
        // This flag exists for future interrupt-driven completion handling.
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

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtioNetHeader {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
}

struct NetBuffer {
    region: DmaRegion,
    header_offset: usize,
    data_offset: usize,
    data_len: usize,
}

impl NetBuffer {
    fn new(provider: &mut DmaRegionProvider, data_len: usize) -> Result<Self, DmaError> {
        let header_size = core::mem::size_of::<VirtioNetHeader>();
        let total = header_size + data_len;
        let page_bytes = PageSize::SIZE_4K.bytes();
        let size = align_up(total, page_bytes);
        let mut region = provider.allocate(size, page_bytes)?;
        region.as_bytes_mut().fill(0);
        Ok(Self {
            region,
            header_offset: 0,
            data_offset: header_size,
            data_len,
        })
    }

    fn header_len(&self) -> usize {
        self.data_offset
    }

    fn total_len_for_payload(&self, payload_len: usize) -> usize {
        self.data_offset + payload_len
    }

    fn data_len(&self) -> usize {
        self.data_len
    }

    fn header_phys(&self) -> PhysAddr {
        self.region.phys_base()
    }

    fn data_phys(&self) -> Option<PhysAddr> {
        self.region.phys_base().checked_add(self.data_offset)
    }

    fn header_ptr(&self) -> *mut VirtioNetHeader {
        self.region
            .virt_base()
            .checked_add(self.header_offset)
            .expect("header virt overflow")
            .into_mut_ptr() as *mut VirtioNetHeader
    }

    fn data_mut(&mut self) -> &mut [u8] {
        let virt = self
            .region
            .virt_base()
            .checked_add(self.data_offset)
            .expect("data virt overflow");
        unsafe { core::slice::from_raw_parts_mut(virt.into_mut_ptr(), self.data_len) }
    }

    fn data(&self) -> &[u8] {
        let virt = self
            .region
            .virt_base()
            .checked_add(self.data_offset)
            .expect("data virt overflow");
        unsafe { core::slice::from_raw_parts(virt.into_ptr(), self.data_len) }
    }

    fn prepare_tx(&mut self, frame: &[u8]) -> Result<(), VirtioNetError> {
        if frame.len() > self.data_len {
            return Err(VirtioNetError::FrameTooLarge(frame.len()));
        }
        let header = VirtioNetHeader::default();
        unsafe {
            core::ptr::write_volatile(self.header_ptr(), header);
        }
        let data = self.data_mut();
        data[..frame.len()].copy_from_slice(frame);
        Ok(())
    }
}

fn write_rx_descriptors(queue: &mut QueueState, head: u16, buffer: &NetBuffer) {
    let header_len = buffer.header_len();
    let slices = queue.memory.slices();
    let head_index = head as usize;
    let data_index = head_index + 1;
    slices.descriptors[head_index] = Descriptor {
        addr: buffer.header_phys().as_raw() as u64,
        len: header_len as u32,
        flags: DescriptorFlags::NEXT.bits() | DescriptorFlags::WRITE.bits(),
        next: head + 1,
    };
    slices.descriptors[data_index] = Descriptor {
        addr: buffer.data_phys().expect("rx data phys missing").as_raw() as u64,
        len: buffer.data_len() as u32,
        flags: DescriptorFlags::WRITE.bits(),
        next: 0,
    };
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

    fn test_complete_with_id(&mut self, id: u32, len: u32) {
        let mut slices = self.memory.slices();
        let slot = (self.used_idx % self.size) as usize;
        let ring = slices.used.ring();
        unsafe {
            core::ptr::write_volatile(&mut ring[slot], UsedElem { id, len });
        }
        let next = self.used_idx.wrapping_add(1);
        slices.used.set_idx(next);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    use crate::device::virtio::queue::QueueConfig;
    use crate::device::virtio::transport::QueueNotifier;
    use crate::println;
    use crate::test::kernel_test_case;

    #[kernel_test_case]
    fn net_buffer_copies_frame() {
        println!("[test] net_buffer_copies_frame");

        let mut provider = DmaRegionProvider::new();
        let mut buffer = NetBuffer::new(&mut provider, 128).expect("dma alloc");
        let payload = [0xABu8; 64];
        buffer.prepare_tx(&payload).expect("prepare tx");
        assert_eq!(&buffer.data()[..payload.len()], &payload);
    }

    #[kernel_test_case]
    fn virtio_net_tx_completes() {
        println!("[test] virtio_net_tx_completes");

        let transport = MockTransport::default();
        let mut device = VirtioNetDevice::new("testnet".into(), transport).expect("device init");
        device.set_completion_hook(|queue, head| {
            queue.test_complete_with_id(head as u32, 0);
        });
        let frame = [0x11u8; 60];
        device.transmit_frame(&frame).expect("tx");
    }

    #[kernel_test_case]
    fn virtio_net_rejects_large_frame() {
        println!("[test] virtio_net_rejects_large_frame");

        let transport = MockTransport::default();
        let mut device = VirtioNetDevice::new("testnet".into(), transport).expect("device init");
        let frame = [0u8; MAX_FRAME_SIZE + 1];
        match device.transmit_frame(&frame) {
            Err(VirtioNetError::FrameTooLarge(_)) => {}
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[kernel_test_case]
    fn virtio_net_rx_reports_small_buffer() {
        println!("[test] virtio_net_rx_reports_small_buffer");

        let transport = MockTransport::default();
        let mut device = VirtioNetDevice::new("testnet".into(), transport).expect("device init");

        let header_len = device.rx_buffers[0].header_len();
        let payload_len = 64;
        let used_len = (header_len + payload_len) as u32;
        device.rx_queue.test_complete_with_id(0, used_len);

        let mut out = [0u8; 32];
        match device.receive_frame(&mut out) {
            Err(VirtioNetError::BufferTooSmall { .. }) => {}
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[kernel_test_case]
    fn virtio_net_rx_polls_frame() {
        println!("[test] virtio_net_rx_polls_frame");

        let transport = MockTransport::default();
        let mut device = VirtioNetDevice::new("testnet".into(), transport).expect("device init");

        let payload = [0x42u8; 32];
        let header_len = device.rx_buffers[0].header_len();
        device.rx_buffers[0].data_mut()[..payload.len()].copy_from_slice(&payload);
        let used_len = (header_len + payload.len()) as u32;
        device.rx_queue.test_complete_with_id(0, used_len);

        let mut out = [0u8; 64];
        let size = device.receive_frame(&mut out).expect("rx").expect("frame");
        assert_eq!(size, payload.len());
        assert_eq!(&out[..size], &payload);
    }

    /// Validates virtio-net is present under QEMU test runs.
    ///
    /// # Implicit dependency
    /// Relies on `xtask::run_qemu` attaching a `virtio-net-pci` device with user networking
    /// during `cargo xtask test`.
    #[kernel_test_case]
    fn virtio_net_present_integration() {
        println!("[test] virtio_net_present_integration");

        with_devices(|devices| {
            assert!(
                !devices.is_empty(),
                "virtio-net integration test requires a network device"
            );
            let device = devices[0].lock();
            let mac = device.mac_address();
            assert!(mac.iter().any(|byte| *byte != 0));
        });
    }

    /// Sends a best-effort Ethernet frame through the QEMU-backed virtio-net device.
    ///
    /// # Implicit dependency
    /// Relies on `xtask::run_qemu` attaching a `virtio-net-pci` device with user networking
    /// during `cargo xtask test`.
    #[kernel_test_case]
    fn virtio_net_tx_integration() {
        println!("[test] virtio_net_tx_integration");

        with_devices(|devices| {
            assert!(
                !devices.is_empty(),
                "virtio-net integration test requires a network device"
            );
            let mut device = devices[0].lock();
            let mut frame = [0u8; 60];
            frame[..6].fill(0xFF);
            frame[6..12].copy_from_slice(&device.mac_address());
            frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // ARP ether type
            device
                .test_transmit_with_timeout(&frame, 1_000_000)
                .expect("tx completion");
        });
    }

    #[kernel_test_case]
    fn virtio_net_tx_reuses_descriptor() {
        println!("[test] virtio_net_tx_reuses_descriptor");

        let transport = MockTransport::default();
        let mut device = VirtioNetDevice::new("testnet".into(), transport).expect("device init");
        device.set_completion_hook(|queue, head| {
            queue.test_complete_with_id(head as u32, 0);
        });

        let frame = [0xABu8; 60];
        device.transmit_frame(&frame).expect("tx 1");
        device.transmit_frame(&frame).expect("tx 2");
    }

    #[kernel_test_case]
    fn virtio_net_rx_reinitializes_descriptors() {
        println!("[test] virtio_net_rx_reinitializes_descriptors");

        let transport = MockTransport::default();
        let mut device = VirtioNetDevice::new("testnet".into(), transport).expect("device init");

        let header_len = device.rx_buffers[0].header_len();
        let used_len = header_len as u32;
        device.rx_queue.test_complete_with_id(0, used_len);

        let mut out = [0u8; 16];
        let _ = device.receive_frame(&mut out).expect("rx");

        let mut slices = device.rx_queue.memory.slices();
        let desc0 = slices.descriptors[0];
        let desc1 = slices.descriptors[1];
        assert_eq!(
            desc0.flags,
            DescriptorFlags::NEXT.bits() | DescriptorFlags::WRITE.bits()
        );
        assert_eq!(desc0.next, 1);
        assert_eq!(desc1.flags, DescriptorFlags::WRITE.bits());
    }

    #[derive(Clone)]
    struct MockTransport {
        status: Cell<DeviceStatus>,
        device_features: u32,
        driver_features: Cell<u32>,
        queue_size: Cell<u16>,
        selected_queue: Cell<u16>,
        cfg: [u8; 8],
    }

    impl Default for MockTransport {
        fn default() -> Self {
            let mut cfg = [0u8; 8];
            cfg[..6].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
            cfg[6] = 1;
            cfg[7] = 0;
            Self {
                status: Cell::new(DeviceStatus::empty()),
                device_features: FeatureBits::MAC.bits() | FeatureBits::STATUS.bits(),
                driver_features: Cell::new(0),
                queue_size: Cell::new(8),
                selected_queue: Cell::new(0),
                cfg,
            }
        }
    }

    impl Transport for MockTransport {
        fn device_id(&self) -> u16 {
            0x1041
        }

        fn read_device_features(&self, _select: u32) -> u32 {
            self.device_features
        }

        fn write_driver_features(&self, _select: u32, value: u32) {
            self.driver_features.set(value);
        }

        fn num_queues(&self) -> u16 {
            2
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

    impl VirtioNetTransport for MockTransport {
        fn config_len(&self) -> usize {
            self.cfg.len()
        }

        fn read_config_bytes(&self, offset: usize, out: &mut [u8]) -> Result<(), TransportError> {
            let end = offset
                .checked_add(out.len())
                .ok_or(TransportError::NotifyUnavailable)?;
            if end > self.cfg.len() {
                return Err(TransportError::NotifyUnavailable);
            }
            out.copy_from_slice(&self.cfg[offset..end]);
            Ok(())
        }
    }
}
