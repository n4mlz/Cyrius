use core::fmt;

use crate::mem::addr::{MemPerm, Page, PageSize, PhysAddr, VirtAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    AlreadyMapped,
    NotMapped,
    FrameAllocationFailed,
    UnsupportedPageSize(PageSize),
    MisalignedFrame,
    NonCanonical,
    InternalError,
}

impl fmt::Display for MapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyMapped => write!(f, "page is already mapped"),
            Self::NotMapped => write!(f, "page is not mapped"),
            Self::FrameAllocationFailed => write!(f, "frame allocation failed"),
            Self::UnsupportedPageSize(size) => {
                write!(f, "unsupported page size {} bytes", size.bytes())
            }
            Self::MisalignedFrame => write!(f, "frame is not aligned to the requested page size"),
            Self::NonCanonical => write!(f, "virtual address is not canonical"),
            Self::InternalError => write!(f, "internal paging error"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmapError {
    NotMapped,
    UnsupportedPageSize(PageSize),
    HugePage, // indicates a mapping backed by a huge page when a smaller size was expected
}

impl fmt::Display for UnmapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotMapped => write!(f, "page is not mapped"),
            Self::UnsupportedPageSize(size) => {
                write!(f, "unsupported page size {} bytes", size.bytes())
            }
            Self::HugePage => write!(f, "encountered a huge page mapping"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslationError {
    NotMapped,
    HugePage,
}

impl fmt::Display for TranslationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotMapped => write!(f, "address is not mapped"),
            Self::HugePage => write!(f, "address translation relies on a huge page mapping"),
        }
    }
}

/// Allocates physical frames used for page table management.
///
/// Frames returned by this trait are implicitly required to be accessible through the active
/// [`PhysMapper`] implementation so that page table code can initialise the frame contents.
pub trait FrameAllocator {
    /// Allocate a frame with the specified size. Implementations may ignore sizes they do not
    /// support and return `None` in such cases.
    fn allocate(&mut self, size: PageSize) -> Option<Page<PhysAddr>>;

    /// Release a frame back to the allocator for reuse. The default implementation is a no-op.
    fn deallocate(&mut self, _frame: Page<PhysAddr>) {}
}

/// Provides a mechanism to temporarily access physical memory from the kernel's address space.
///
/// # Safety
///
/// Implementations must ensure that the returned virtual address refers to a valid, exclusive
/// mapping of the requested physical memory for the duration of the caller's use. Callers must not
/// retain the mapping beyond the lifetime guaranteed by the implementation.
pub trait PhysMapper {
    /// Translate a physical address into a virtual address that is accessible by the kernel.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the returned virtual address is used only while the mapping
    /// remains valid and that it does not introduce aliasing with other active mappings.
    unsafe fn phys_to_virt(&self, addr: PhysAddr) -> VirtAddr;

    /// Translate a virtual address returned by [`Self::phys_to_virt`] back to its physical
    /// counterpart.
    fn virt_to_phys(&self, addr: VirtAddr) -> PhysAddr;
}

/// Unified interface for page table operations independent of the underlying paging strategy.
pub trait PageTableOps {
    /// Map a virtual page to a physical frame with the requested permissions.
    fn map<A: FrameAllocator>(
        &mut self,
        page: Page<VirtAddr>,
        frame: Page<PhysAddr>,
        perms: MemPerm,
        allocator: &mut A,
    ) -> Result<(), MapError>;

    /// Unmap a previously mapped page and return the backing physical frame.
    fn unmap(&mut self, page: Page<VirtAddr>) -> Result<Page<PhysAddr>, UnmapError>;

    /// Translate an arbitrary virtual address to its physical counterpart.
    fn translate(&self, addr: VirtAddr) -> Result<PhysAddr, TranslationError>;

    /// Update permissions on an already mapped page.
    fn update_permissions(&mut self, page: Page<VirtAddr>, perms: MemPerm) -> Result<(), MapError>;

    /// Return the physical frame containing the root page table.
    fn root(&self) -> Page<PhysAddr>;
}
