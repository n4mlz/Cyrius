use alloc::vec::Vec;

use crate::mem::addr::{Page, PageSize, PhysAddr, VirtAddr, VirtIntoPtr};
use crate::mem::manager;
use crate::mem::paging::{FrameAllocator, PhysMapper};

const PAGE_BYTES: usize = PageSize::SIZE_4K.bytes();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaError {
    InvalidSize,
    AlignmentNotPowerOfTwo,
    AlignmentTooLarge,
    AllocationFailed,
}

#[derive(Debug, Default)]
pub struct DmaRegionProvider;

impl DmaRegionProvider {
    pub const fn new() -> Self {
        Self
    }

    pub fn allocate(&mut self, size: usize, align: usize) -> Result<DmaRegion, DmaError> {
        allocate_region(size, align)
    }
}

/// Represents a physically contiguous DMA buffer together with its kernel virtual alias.
///
/// # Implicit dependency
/// Requires the bootloader-provided offset mapping exposed via [`manager::phys_mapper`] so that
/// every physical page in the run is reachable from the kernel address space.
pub struct DmaRegion {
    phys: PhysAddr,
    virt: VirtAddr,
    len: usize,
    frames: Vec<Page<PhysAddr>>,
}

impl DmaRegion {
    pub fn phys_base(&self) -> PhysAddr {
        self.phys
    }

    pub fn virt_base(&self) -> VirtAddr {
        self.virt
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns a mutable byte slice backed by the DMA region.
    ///
    /// # Implicit dependency
    /// Relies on the bootloader-provided physical memory mapping being accessible through
    /// [`manager::phys_mapper`] so that DMA memory is visible in the kernel's virtual address space.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.virt.into_mut_ptr(), self.len) }
    }

    #[cfg(test)]
    pub fn debug_pages(&self) -> &[Page<PhysAddr>] {
        &self.frames
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

fn allocate_region(size: usize, align: usize) -> Result<DmaRegion, DmaError> {
    if size == 0 {
        return Err(DmaError::InvalidSize);
    }

    let alignment = if align == 0 { PAGE_BYTES } else { align };
    if !alignment.is_power_of_two() {
        return Err(DmaError::AlignmentNotPowerOfTwo);
    }
    if alignment > PAGE_BYTES {
        return Err(DmaError::AlignmentTooLarge);
    }

    let page_count = align_up(size, PAGE_BYTES) / PAGE_BYTES;
    let mut allocator = manager::frame_allocator();
    let frames = allocator
        .allocate_contiguous(page_count, PageSize::SIZE_4K)
        .ok_or(DmaError::AllocationFailed)?;

    let phys = frames
        .first()
        .map(|page| page.start)
        .ok_or(DmaError::AllocationFailed)?;
    let mapper = manager::phys_mapper();
    let virt = unsafe { mapper.phys_to_virt(phys) };

    Ok(DmaRegion {
        phys,
        virt,
        len: page_count * PAGE_BYTES,
        frames,
    })
}

fn align_up(value: usize, align: usize) -> usize {
    if align == 0 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::addr::Addr;
    use crate::test::kernel_test_case;

    #[kernel_test_case]
    fn allocates_single_page() {
        let mut provider = DmaRegionProvider::new();
        let mut region = provider
            .allocate(512, PAGE_BYTES)
            .expect("dma region allocation must succeed");
        assert_eq!(region.len(), PAGE_BYTES);
        assert!(region.phys_base().is_aligned(PAGE_BYTES));
        let bytes = region.as_bytes_mut();
        bytes[0] = 0xAA;
        bytes[PAGE_BYTES - 1] = 0x55;
    }

    #[kernel_test_case]
    fn rejects_large_alignment() {
        let mut provider = DmaRegionProvider::new();
        let result = provider.allocate(PAGE_BYTES, PAGE_BYTES * 2);
        assert!(matches!(result, Err(DmaError::AlignmentTooLarge)));
    }
}
