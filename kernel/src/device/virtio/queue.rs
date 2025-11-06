use crate::mem::addr::{Addr, PhysAddr, VirtAddr};

/// Descriptor table entry as defined by the VirtIO specification.
#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default)]
pub struct Descriptor {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

impl Descriptor {
    pub const F_NEXT: u16 = 1;
    pub const F_WRITE: u16 = 2;
    pub const F_INDIRECT: u16 = 4;
}

/// Layout metadata for allocating a virtqueue in contiguous guest memory.
#[derive(Clone, Copy, Debug)]
pub struct VirtQueueLayout {
    queue_size: u16,
    desc_offset: usize,
    avail_offset: usize,
    used_offset: usize,
    total_size: usize,
}

impl VirtQueueLayout {
    const DESC_ENTRY_SIZE: usize = core::mem::size_of::<Descriptor>();
    const AVAIL_HEADER_SIZE: usize = 2 + 2 + 2;
    const USED_HEADER_SIZE: usize = 2 + 2;
    const USED_ELEMENT_SIZE: usize = 8;

    /// Construct layout metadata for the provided queue depth.
    ///
    /// # Panics
    ///
    /// Panics if `queue_size` is zero or not a power of two, as required by the VirtIO spec.
    pub fn new(queue_size: u16) -> Self {
        assert!(queue_size != 0, "virtqueue size must be non-zero");
        assert!(
            queue_size.is_power_of_two(),
            "virtqueue size must be a power of two"
        );

        let desc_offset = 0;
        let desc_size = Self::DESC_ENTRY_SIZE * queue_size as usize;
        let avail_offset = desc_offset + desc_size;
        let avail_size = Self::AVAIL_HEADER_SIZE + 2 * queue_size as usize;
        let avail_padded = align_up(avail_size, core::mem::size_of::<u16>());
        let used_offset = align_up(avail_offset + avail_padded, 4096);
        let used_size = Self::USED_HEADER_SIZE + Self::USED_ELEMENT_SIZE * queue_size as usize;
        let used_padded = align_up(used_size, core::mem::size_of::<u32>());
        let total_size = used_offset + used_padded;

        Self {
            queue_size,
            desc_offset,
            avail_offset,
            used_offset,
            total_size,
        }
    }

    /// Return the number of queue entries.
    pub fn queue_size(&self) -> u16 {
        self.queue_size
    }

    /// Return the total amount of memory in bytes required for the queue.
    pub fn total_size(&self) -> usize {
        self.total_size
    }

    /// Project the layout onto the provided base physical address.
    pub fn region_from(self, base: PhysAddr) -> VirtQueueRegion {
        VirtQueueRegion {
            descriptor: base,
            driver: base
                .checked_add(self.avail_offset)
                .expect("virtqueue avail offset overflow"),
            device: base
                .checked_add(self.used_offset)
                .expect("virtqueue used offset overflow"),
            total_len: self.total_size,
        }
    }

    /// Return the virtual address offsets to assist with mapping the queue into a virtual address space.
    pub fn virtual_offsets(&self) -> VirtQueueOffsets {
        VirtQueueOffsets {
            descriptor: self.desc_offset,
            driver: self.avail_offset,
            device: self.used_offset,
        }
    }
}

/// Virtual address offsets derived from a [`VirtQueueLayout`].
#[derive(Clone, Copy, Debug)]
pub struct VirtQueueOffsets {
    pub descriptor: usize,
    pub driver: usize,
    pub device: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct VirtQueueRegion {
    pub descriptor: PhysAddr,
    pub driver: PhysAddr,
    pub device: PhysAddr,
    total_len: usize,
}

impl VirtQueueRegion {
    /// Return the total length of the backing allocation.
    pub fn len(&self) -> usize {
        self.total_len
    }

    /// Return whether the region length is zero.
    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }

    /// Translate the region into virtual addresses for mapping helpers.
    pub fn into_virtual(self, base: VirtAddr) -> VirtQueueVirtualRegion {
        VirtQueueVirtualRegion {
            descriptor: base,
            driver: base
                .checked_add(self.driver.as_raw() - self.descriptor.as_raw())
                .expect("virtqueue driver offset overflow"),
            device: base
                .checked_add(self.device.as_raw() - self.descriptor.as_raw())
                .expect("virtqueue device offset overflow"),
            total_len: self.total_len,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VirtQueueVirtualRegion {
    pub descriptor: VirtAddr,
    pub driver: VirtAddr,
    pub device: VirtAddr,
    total_len: usize,
}

impl VirtQueueVirtualRegion {
    pub fn len(&self) -> usize {
        self.total_len
    }

    pub fn is_empty(&self) -> bool {
        self.total_len == 0
    }
}

fn align_up(value: usize, align: usize) -> usize {
    assert!(align.is_power_of_two(), "alignment must be a power of two");
    (value + align - 1) & !(align - 1)
}
