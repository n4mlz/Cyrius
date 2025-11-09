use core::mem::size_of;

use crate::mem::addr::{Addr, PhysAddr, VirtIntoPtr};
use crate::mem::dma::{DmaError, DmaRegion, DmaRegionProvider};

const VRING_ALIGN: usize = 4096;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Descriptor {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

bitflags::bitflags! {
    pub struct DescriptorFlags: u16 {
        const NEXT = 1;
        const WRITE = 2;
        const INDIRECT = 4;
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UsedElem {
    pub id: u32,
    pub len: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct AvailHeader {
    flags: u16,
    idx: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct UsedHeader {
    flags: u16,
    idx: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct QueueAllocation {
    pub size: usize,
    pub align: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct QueueConfig {
    pub descriptor_area: PhysAddr,
    pub avail_area: PhysAddr,
    pub used_area: PhysAddr,
}

impl QueueConfig {
    pub fn new(descriptor_area: PhysAddr, avail_area: PhysAddr, used_area: PhysAddr) -> Self {
        Self {
            descriptor_area,
            avail_area,
            used_area,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueError {
    ZeroSize,
    ExceedsMax,
    NotPowerOfTwo,
    RegionTooSmall { required: usize, actual: usize },
    Dma(DmaError),
}

#[derive(Debug, Clone, Copy)]
struct QueueLayout {
    index: u16,
    size: u16,
    desc_offset: usize,
    avail_offset: usize,
    used_offset: usize,
    total_len: usize,
}

impl QueueLayout {
    fn new(index: u16, size: u16) -> Result<Self, QueueError> {
        if size == 0 {
            return Err(QueueError::ZeroSize);
        }
        if size > 4096 {
            return Err(QueueError::ExceedsMax);
        }
        if !size.is_power_of_two() {
            return Err(QueueError::NotPowerOfTwo);
        }

        let desc_bytes = size as usize * size_of::<Descriptor>();
        let avail_ring_bytes =
            size_of::<AvailHeader>() + size_of::<u16>() * size as usize + size_of::<u16>();
        let used_ring_bytes =
            size_of::<UsedHeader>() + size_of::<UsedElem>() * size as usize + size_of::<u16>();

        let avail_offset = desc_bytes;
        let used_offset = align_up(desc_bytes + avail_ring_bytes, VRING_ALIGN);
        let total_len = used_offset + used_ring_bytes;

        Ok(Self {
            index,
            size,
            desc_offset: 0,
            avail_offset,
            used_offset,
            total_len,
        })
    }
}

fn align_up(value: usize, align: usize) -> usize {
    if align == 0 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}

pub struct QueueMemory {
    layout: QueueLayout,
    region: DmaRegion,
}

impl QueueMemory {
    pub fn requirements(size: u16) -> Result<QueueAllocation, QueueError> {
        let layout = QueueLayout::new(0, size)?;
        Ok(QueueAllocation {
            size: layout.total_len,
            align: VRING_ALIGN,
        })
    }

    pub fn allocate(
        index: u16,
        size: u16,
        provider: &mut DmaRegionProvider,
    ) -> Result<Self, QueueError> {
        let requirements = Self::requirements(size)?;
        let region = provider
            .allocate(requirements.size, requirements.align)
            .map_err(QueueError::Dma)?;
        Self::from_region(index, size, region)
    }

    pub fn from_region(index: u16, size: u16, mut region: DmaRegion) -> Result<Self, QueueError> {
        let layout = QueueLayout::new(index, size)?;
        if region.len() < layout.total_len {
            return Err(QueueError::RegionTooSmall {
                required: layout.total_len,
                actual: region.len(),
            });
        }
        region.as_bytes_mut().fill(0);
        Ok(Self { layout, region })
    }

    pub fn queue_index(&self) -> u16 {
        self.layout.index
    }

    pub fn queue_size(&self) -> u16 {
        self.layout.size
    }

    pub fn config(&self) -> QueueConfig {
        let base = self.region.phys_base();
        let avail = base
            .checked_add(self.layout.avail_offset)
            .expect("avail region overflow");
        let used = base
            .checked_add(self.layout.used_offset)
            .expect("used region overflow");
        QueueConfig::new(base, avail, used)
    }

    pub fn slices(&mut self) -> QueueSlices<'_> {
        let base_ptr = self.region.virt_base().into_mut_ptr();
        let desc_ptr = unsafe { base_ptr.add(self.layout.desc_offset) } as *mut Descriptor;
        let desc = unsafe { core::slice::from_raw_parts_mut(desc_ptr, self.layout.size as usize) };

        let avail_ptr = unsafe { base_ptr.add(self.layout.avail_offset) };
        let avail = unsafe { AvailRing::new(avail_ptr, self.layout.size as usize) };

        let used_ptr = unsafe { base_ptr.add(self.layout.used_offset) };
        let used = unsafe { UsedRing::new(used_ptr, self.layout.size as usize) };

        QueueSlices {
            descriptors: desc,
            avail,
            used,
        }
    }
}

pub struct QueueSlices<'a> {
    pub descriptors: &'a mut [Descriptor],
    pub avail: AvailRing<'a>,
    pub used: UsedRing<'a>,
}

pub struct AvailRing<'a> {
    header: &'a mut AvailHeader,
    ring: &'a mut [u16],
    used_event: &'a mut u16,
}

impl<'a> AvailRing<'a> {
    unsafe fn new(base: *mut u8, size: usize) -> Self {
        unsafe {
            let header = &mut *(base as *mut AvailHeader);
            let ring_ptr = base.add(size_of::<AvailHeader>()) as *mut u16;
            let ring = core::slice::from_raw_parts_mut(ring_ptr, size);
            let used_event_ptr = ring_ptr.add(size) as *mut u16;
            let used_event = &mut *used_event_ptr;
            Self {
                header,
                ring,
                used_event,
            }
        }
    }

    pub fn flags(&self) -> u16 {
        self.header.flags
    }

    pub fn set_flags(&mut self, value: u16) {
        self.header.flags = value;
    }

    pub fn idx(&self) -> u16 {
        self.header.idx
    }

    pub fn set_idx(&mut self, value: u16) {
        self.header.idx = value;
    }

    pub fn ring(&mut self) -> &mut [u16] {
        self.ring
    }

    pub fn used_event(&mut self) -> &mut u16 {
        self.used_event
    }
}

pub struct UsedRing<'a> {
    header: &'a mut UsedHeader,
    ring: &'a mut [UsedElem],
    avail_event: &'a mut u16,
}

impl<'a> UsedRing<'a> {
    unsafe fn new(base: *mut u8, size: usize) -> Self {
        unsafe {
            let header = &mut *(base as *mut UsedHeader);
            let ring_ptr = base.add(size_of::<UsedHeader>()) as *mut UsedElem;
            let ring = core::slice::from_raw_parts_mut(ring_ptr, size);
            let avail_event_ptr = ring_ptr.add(size) as *mut u16;
            let avail_event = &mut *avail_event_ptr;
            Self {
                header,
                ring,
                avail_event,
            }
        }
    }

    pub fn flags(&self) -> u16 {
        self.header.flags
    }

    pub fn set_flags(&mut self, value: u16) {
        self.header.flags = value;
    }

    pub fn idx(&self) -> u16 {
        self.header.idx
    }

    pub fn set_idx(&mut self, value: u16) {
        self.header.idx = value;
    }

    pub fn ring(&mut self) -> &mut [UsedElem] {
        self.ring
    }

    pub fn avail_event(&mut self) -> &mut u16 {
        self.avail_event
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::kernel_test_case;

    #[kernel_test_case]
    fn allocation_size_matches_spec() {
        let req = QueueMemory::requirements(256).expect("queue size valid");
        assert_eq!(req.align, VRING_ALIGN);
        assert_eq!(req.size, 10_246);
    }

    #[kernel_test_case]
    fn reject_non_power_of_two() {
        match QueueMemory::requirements(3) {
            Err(QueueError::NotPowerOfTwo) => {}
            other => panic!("unexpected result: {:?}", other),
        }
    }
}
