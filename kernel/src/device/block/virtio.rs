use core::convert::TryFrom;
use core::mem::size_of;
use core::sync::atomic::{Ordering, fence};

use crate::device::block::BlockDevice;
use crate::device::virtio::dma::{DmaAllocator, DmaError, DmaRegion};
use crate::device::virtio::queue::{Descriptor, VirtQueueLayout};
use crate::device::virtio::{PciTransport, PciTransportError, features, status};
use crate::device::{Device, DeviceType};
use crate::mem::addr::{PhysAddr, VirtIntoPtr};
use crate::util::spinlock::SpinLock;

const QUEUE_INDEX: u16 = 0;
const QUEUE_DEPTH: u16 = 8;
const REQUEST_STATUS_SIZE: usize = 1;
const CONFIG_CAPACITY_OFFSET: usize = 0x00;
const CONFIG_BLK_SIZE_OFFSET: usize = 0x14;

const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_T_FLUSH: u32 = 4;

const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

#[repr(C, packed)]
struct RequestHeader {
    request_type: u32,
    reserved: u32,
    sector: u64,
}

pub struct VirtioBlockDevice {
    name: &'static str,
    transport: PciTransport,
    queue: SpinLock<QueueState>,
    block_size: u32,
    capacity_sectors: u64,
    _negotiated_features: u64,
    flush_supported: bool,
}

struct QueueState {
    layout: VirtQueueLayout,
    region: DmaRegion,
    avail_index: u16,
}

impl VirtioBlockDevice {
    pub fn new(name: &'static str, mut transport: PciTransport) -> Result<Self, VirtioBlockError> {
        transport.set_status(0)?;

        let mut status_bits = status::ACKNOWLEDGE;
        transport.set_status(status_bits)?;

        status_bits |= status::DRIVER;
        transport.set_status(status_bits)?;

        let device_features = transport.read_device_features()?;
        if device_features & features::VERSION_1 == 0 {
            return Err(VirtioBlockError::MissingFeature("VERSION_1"));
        }

        // Build desired feature set (intersection with device features)
        let mut driver_desired = features::VERSION_1;
        if device_features & features::WRITEBACK != 0 {
            driver_desired |= features::WRITEBACK;
        }
        let flush_supported = device_features & VIRTIO_BLK_F_FLUSH != 0;
        if flush_supported {
            driver_desired |= VIRTIO_BLK_F_FLUSH;
        }
        // Negotiate NOTIFICATION_DATA if device supports it
        if device_features & features::NOTIFICATION_DATA != 0 {
            driver_desired |= features::NOTIFICATION_DATA;
        }

        // Agreed feature set is the intersection of device and driver desired features
        let agreed = device_features & driver_desired;
        transport.write_driver_features(agreed)?;

        status_bits |= status::FEATURES_OK;
        transport.set_status(status_bits)?;
        if transport.status()? & status::FEATURES_OK == 0 {
            return Err(VirtioBlockError::FeaturesRejected);
        }

        transport.select_queue(QUEUE_INDEX)?;
        let max_size = transport.queue_size_max()?;
        let mut queue_size = max_size.min(QUEUE_DEPTH);
        while queue_size > 0 && !queue_size.is_power_of_two() {
            queue_size -= 1;
        }
        if queue_size < 3 {
            return Err(VirtioBlockError::QueueTooSmall {
                available: max_size,
            });
        }
        transport.set_queue_size(queue_size)?;

        let layout = VirtQueueLayout::new(queue_size);
        let mut region = DmaAllocator::allocate(layout.total_size())?;
        region.zero();

        let queue_region = layout.region_from(region.phys_start());
        transport.configure_queue(queue_region)?;
        transport.set_queue_ready(true)?;

        let capacity_sectors = transport.read_config::<u64>(CONFIG_CAPACITY_OFFSET)?;
        let block_size = if device_features & VIRTIO_BLK_F_BLK_SIZE != 0 {
            let size = transport.read_config::<u32>(CONFIG_BLK_SIZE_OFFSET)?;
            if size == 0 { 512 } else { size }
        } else {
            512
        };

        status_bits |= status::DRIVER_OK;
        transport.set_status(status_bits)?;

        let queue = QueueState {
            layout,
            region,
            avail_index: 0,
        };

        let device = Self {
            name,
            transport,
            queue: SpinLock::new(queue),
            block_size,
            capacity_sectors,
            _negotiated_features: agreed,
            flush_supported,
        };

        #[cfg(debug_assertions)]
        crate::println!(
            "[virtio-blk] {}: queue={} block={} capacity={} sectors features=0x{:x}",
            name,
            queue_size,
            block_size,
            capacity_sectors,
            agreed
        );

        Ok(device)
    }

    pub fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }

    fn submit_read(&self, lba: u64, buffer: &mut [u8]) -> Result<(), VirtioBlockError> {
        self.submit_request(VIRTIO_BLK_T_IN, lba, RequestData::Read(buffer))
    }

    fn submit_write(&self, lba: u64, buffer: &[u8]) -> Result<(), VirtioBlockError> {
        self.submit_request(VIRTIO_BLK_T_OUT, lba, RequestData::Write(buffer))
    }

    fn submit_flush(&self) -> Result<(), VirtioBlockError> {
        self.submit_request(VIRTIO_BLK_T_FLUSH, 0, RequestData::None)
    }

    fn submit_request(
        &self,
        request_type: u32,
        lba: u64,
        data: RequestData<'_>,
    ) -> Result<(), VirtioBlockError> {
        let block_size = self.block_size as usize;

        let (data_len, write_src, read_dst) = match data {
            RequestData::Read(dst) => (dst.len(), None, Some(dst)),
            RequestData::Write(src) => (src.len(), Some(src), None),
            RequestData::None => (0, None, None),
        };

        if data_len % block_size != 0 {
            return Err(VirtioBlockError::BufferAlignment {
                len: data_len,
                block_size,
            });
        }

        let header_size = size_of::<RequestHeader>();
        let total_size = header_size + data_len + REQUEST_STATUS_SIZE;
        let mut dma = DmaAllocator::allocate(total_size)?;

        let header_phys = dma.phys_at_offset(0).ok_or(VirtioBlockError::DmaBounds)?;
        let data_phys = if data_len == 0 {
            None
        } else {
            Some(
                dma.phys_at_offset(header_size)
                    .ok_or(VirtioBlockError::DmaBounds)?,
            )
        };
        let status_phys = dma
            .phys_at_offset(header_size + data_len)
            .ok_or(VirtioBlockError::DmaBounds)?;

        let used_len = header_size + data_len + REQUEST_STATUS_SIZE;
        let buffer = &mut dma.as_mut_slice()[..used_len];

        let (header_buf, rest) = buffer.split_at_mut(header_size);
        let (data_buf, status_buf) = rest.split_at_mut(data_len);
        status_buf.fill(0xFF);

        if let Some(src) = write_src {
            data_buf.copy_from_slice(src);
        }

        let header = RequestHeader {
            request_type,
            reserved: 0,
            sector: lba,
        };

        unsafe {
            core::ptr::write_unaligned(header_buf.as_mut_ptr() as *mut RequestHeader, header);
        }

        let mut queue = self.queue.lock();
        let desc_base = queue.descriptor_table();

        let header_len =
            u32::try_from(header_size).map_err(|_| VirtioBlockError::RequestTooLarge)?;
        write_descriptor(desc_base, 0, header_phys, header_len, Descriptor::F_NEXT, 1);

        let mut next_index = 1;
        if let Some(data_phys) = data_phys {
            let mut flags = Descriptor::F_NEXT;
            if read_dst.is_some() {
                flags |= Descriptor::F_WRITE;
            }
            let data_len_u32 =
                u32::try_from(data_len).map_err(|_| VirtioBlockError::RequestTooLarge)?;
            write_descriptor(desc_base, 1, data_phys, data_len_u32, flags, 2);
            next_index = 2;
        }

        let status_index = next_index;
        write_descriptor(
            desc_base,
            status_index,
            status_phys,
            REQUEST_STATUS_SIZE as u32,
            Descriptor::F_WRITE,
            0,
        );

        fence(Ordering::Release);

        let avail_idx_ptr = queue.avail_idx_ptr();
        let ring_ptr = queue.avail_ring_ptr();
        let used_idx_ptr = queue.used_idx_ptr();
        let queue_size = queue.layout.queue_size();
        let slot = (queue.avail_index % queue_size) as usize;

        unsafe {
            core::ptr::write_volatile(ring_ptr.add(slot), 0);
            queue.avail_index = queue.avail_index.wrapping_add(1);
            core::ptr::write_volatile(avail_idx_ptr, queue.avail_index);
        }

        let expected_used = unsafe { core::ptr::read_volatile(used_idx_ptr) }.wrapping_add(1);

        drop(queue);

        self.transport.notify_queue(QUEUE_INDEX)?;

        loop {
            let used = unsafe { core::ptr::read_volatile(used_idx_ptr) };
            if used == expected_used {
                break;
            }
            core::hint::spin_loop();
        }

        fence(Ordering::Acquire);

        let status = unsafe { core::ptr::read_volatile(status_buf.as_ptr()) };
        match status {
            VIRTIO_BLK_S_OK => {
                if let Some(dst) = read_dst {
                    dst.copy_from_slice(data_buf);
                }
                Ok(())
            }
            VIRTIO_BLK_S_IOERR | VIRTIO_BLK_S_UNSUPP => Err(VirtioBlockError::DeviceStatus(status)),
            other => Err(VirtioBlockError::DeviceStatus(other)),
        }
    }
}

impl QueueState {
    fn descriptor_table(&self) -> *mut Descriptor {
        self.region.virt_start().into_mut_ptr() as *mut Descriptor
    }

    fn avail_base(&self) -> *mut u8 {
        let offsets = self.layout.virtual_offsets();
        self.region
            .virt_at_offset(offsets.driver)
            .expect("virtqueue driver offset out of range")
            .into_mut_ptr()
    }

    fn used_base(&self) -> *mut u8 {
        let offsets = self.layout.virtual_offsets();
        self.region
            .virt_at_offset(offsets.device)
            .expect("virtqueue device offset out of range")
            .into_mut_ptr()
    }

    fn avail_idx_ptr(&mut self) -> *mut u16 {
        unsafe { (self.avail_base() as *mut u16).add(1) }
    }

    fn avail_ring_ptr(&mut self) -> *mut u16 {
        unsafe { (self.avail_base() as *mut u16).add(2) }
    }

    fn used_idx_ptr(&mut self) -> *mut u16 {
        unsafe { (self.used_base() as *mut u16).add(1) }
    }
}

impl Device for VirtioBlockDevice {
    fn name(&self) -> &str {
        self.name
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Block
    }
}

impl BlockDevice for VirtioBlockDevice {
    type Error = VirtioBlockError;

    fn block_size(&self) -> usize {
        self.block_size as usize
    }

    fn read_at(&self, lba: u64, buffer: &mut [u8]) -> Result<(), Self::Error> {
        if buffer.is_empty() {
            return Ok(());
        }
        self.submit_read(lba, buffer)
    }

    fn write_at(&self, lba: u64, buffer: &[u8]) -> Result<(), Self::Error> {
        if buffer.is_empty() {
            return Ok(());
        }
        self.submit_write(lba, buffer)
    }

    fn flush(&self) -> Result<(), Self::Error> {
        if !self.flush_supported {
            return Err(VirtioBlockError::FlushUnsupported);
        }
        self.submit_flush()
    }
}

enum RequestData<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
    None,
}

fn write_descriptor(
    base: *mut Descriptor,
    index: usize,
    addr: PhysAddr,
    len: u32,
    flags: u16,
    next: u16,
) {
    unsafe {
        let desc = base.add(index);
        (*desc).addr = addr.as_raw() as u64;
        (*desc).len = len;
        (*desc).flags = flags;
        (*desc).next = next;
    }
}

#[derive(Debug)]
pub enum VirtioBlockError {
    Transport(PciTransportError),
    Dma(DmaError),
    MissingFeature(&'static str),
    FeaturesRejected,
    QueueTooSmall { available: u16 },
    BufferAlignment { len: usize, block_size: usize },
    RequestTooLarge,
    DmaBounds,
    DeviceStatus(u8),
    FlushUnsupported,
}

impl core::fmt::Display for VirtioBlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(_) => write!(f, "transport error"),
            Self::Dma(_) => write!(f, "dma allocation error"),
            Self::MissingFeature(name) => write!(f, "missing feature {name}"),
            Self::FeaturesRejected => write!(f, "device rejected negotiated features"),
            Self::QueueTooSmall { available } => {
                write!(f, "virtqueue too small: available {available}")
            }
            Self::BufferAlignment { len, block_size } => {
                write!(
                    f,
                    "buffer length {len} not aligned to block size {block_size}"
                )
            }
            Self::RequestTooLarge => write!(f, "request length exceeds descriptor limit"),
            Self::DmaBounds => write!(f, "dma offset out of bounds"),
            Self::DeviceStatus(status) => write!(f, "device reported status 0x{status:02x}"),
            Self::FlushUnsupported => write!(f, "flush not supported by device"),
        }
    }
}

impl From<PciTransportError> for VirtioBlockError {
    fn from(value: PciTransportError) -> Self {
        Self::Transport(value)
    }
}

impl From<DmaError> for VirtioBlockError {
    fn from(value: DmaError) -> Self {
        Self::Dma(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::bus::pci;
    use crate::device::virtio::PciTransport;
    use crate::test::kernel_test_case;

    const TEST_SIGNATURE: &[u8] = b"CYRIUSBL";
    const PCI_VENDOR_VIRTIO: u16 = 0x1AF4;
    const PCI_DEVICE_BLK_MODERN: u16 = 0x1042;

    #[kernel_test_case]
    fn virtio_blk_reads_signature() {
        let Some(pci_dev) = pci::find_device(PCI_VENDOR_VIRTIO, PCI_DEVICE_BLK_MODERN) else {
            crate::println!("[test virtio-blk] skipping: modern virtio-blk PCI device not found");
            return;
        };

        let transport = match PciTransport::new(pci_dev) {
            Ok(transport) => transport,
            Err(err) => {
                crate::println!(
                    "[test virtio-blk] skipping: failed to initialise transport ({err})"
                );
                return;
            }
        };

        let driver = match VirtioBlockDevice::new("virtio-test", transport) {
            Ok(dev) => dev,
            Err(VirtioBlockError::MissingFeature(name)) => {
                crate::println!("[test virtio-blk] skipping: feature {name} missing");
                return;
            }
            Err(other) => panic!("virtio-blk init failed: {other:?}"),
        };

        assert!(driver.block_size() >= 512);

        let mut sector = [0u8; 512];
        driver
            .read_at(0, &mut sector)
            .unwrap_or_else(|err| panic!("virtio-blk read failed: {err:?}"));

        assert_eq!(&sector[..TEST_SIGNATURE.len()], TEST_SIGNATURE);
        assert!(sector[TEST_SIGNATURE.len()..].iter().any(|byte| *byte == 0));
    }
}
