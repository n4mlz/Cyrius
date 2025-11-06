use alloc::vec::Vec;
use core::fmt;

use crate::mem::addr::{Addr, Page, PageSize, PhysAddr, VirtAddr, VirtIntoPtr};
use crate::mem::manager;
use crate::mem::paging::{FrameAllocator, PhysMapper};

/// Provides contiguous DMA-capable memory carved out of the global frame allocator.
///
/// # Notes
///
/// This allocator relies on `mem::manager::frame_allocator()` and the offset-based
/// `phys_mapper()` exported by the same module. Callers must ensure the memory manager is
/// initialised before requesting DMA buffers.
pub struct DmaAllocator;

impl DmaAllocator {
    /// Allocate a DMA region backed by contiguous 4 KiB frames.
    pub fn allocate(size: usize) -> Result<DmaRegion, DmaError> {
        if size == 0 {
            return Err(DmaError::InvalidSize);
        }

        let page_size = PageSize::SIZE_4K.bytes();
        let total_size = align_up(size, page_size).ok_or(DmaError::SizeOverflow)?;
        let page_count = total_size / page_size;

        let mut allocator = manager::frame_allocator();
        let mut frames: Vec<Page<PhysAddr>> = Vec::with_capacity(page_count);

        for _ in 0..page_count {
            let frame = allocator
                .allocate(PageSize::SIZE_4K)
                .ok_or(DmaError::OutOfMemory)?;

            if let Some(prev) = frames.last() {
                let expected = prev
                    .start
                    .checked_add(page_size)
                    .ok_or(DmaError::SizeOverflow)?;
                if expected.as_raw() != frame.start.as_raw() {
                    // Return the current frame and already reserved frames before failing.
                    allocator.deallocate(frame);
                    for owned in frames.drain(..).rev() {
                        allocator.deallocate(owned);
                    }
                    return Err(DmaError::NonContiguous);
                }
            }

            frames.push(frame);
        }

        let phys_start = frames
            .first()
            .map(|page| page.start)
            .ok_or(DmaError::OutOfMemory)?;

        // SAFETY: the physical range is guaranteed to be mapped by the offset mapper during
        // early boot initialisation.
        let virt_start = unsafe { manager::phys_mapper().phys_to_virt(phys_start) };

        Ok(DmaRegion {
            phys_start,
            virt_start,
            len: total_size,
            frames,
        })
    }
}

/// Holds the lifetime of a DMA allocation and returns frames to the allocator on drop.
pub struct DmaRegion {
    phys_start: PhysAddr,
    virt_start: VirtAddr,
    len: usize,
    frames: Vec<Page<PhysAddr>>,
}

impl DmaRegion {
    pub fn phys_start(&self) -> PhysAddr {
        self.phys_start
    }

    pub fn virt_start(&self) -> VirtAddr {
        self.virt_start
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.virt_start.into_mut_ptr()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.virt_start.into_mut_ptr(), self.len) }
    }

    pub fn zero(&mut self) {
        self.as_mut_slice().fill(0);
    }

    /// Translate a byte offset within the DMA region into a physical address.
    pub fn phys_at_offset(&self, offset: usize) -> Option<PhysAddr> {
        self.phys_start.checked_add(offset)
    }

    /// Translate a byte offset within the DMA region into a virtual address.
    pub fn virt_at_offset(&self, offset: usize) -> Option<VirtAddr> {
        self.virt_start.checked_add(offset)
    }
}

impl Drop for DmaRegion {
    fn drop(&mut self) {
        if self.frames.is_empty() {
            return;
        }

        let mut allocator = manager::frame_allocator();
        for frame in self.frames.drain(..) {
            allocator.deallocate(frame);
        }
    }
}

#[derive(Debug)]
pub enum DmaError {
    InvalidSize,
    SizeOverflow,
    OutOfMemory,
    NonContiguous,
}

impl fmt::Display for DmaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSize => write!(f, "size must be greater than zero"),
            Self::SizeOverflow => write!(f, "requested size exceeds addressable range"),
            Self::OutOfMemory => write!(f, "frame allocator unable to supply frames"),
            Self::NonContiguous => write!(f, "allocator returned non-contiguous frames"),
        }
    }
}

fn align_up(value: usize, align: usize) -> Option<usize> {
    debug_assert!(align.is_power_of_two());
    let mask = align - 1;
    value.checked_add(mask).map(|v| v & !mask)
}
