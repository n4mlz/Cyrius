//! Program loading facilities.
//!
//! This module stays architecture-agnostic; architecture-specific glue (e.g., trap entry)
//! should live under `arch/`.

pub mod linux;

/// Architecture hook that exposes page table access for loaders.
pub trait AddressSpaceExt {
    type PageTable<'a>: crate::mem::paging::PageTableOps
    where
        Self: 'a;

    type Allocator<'a>: crate::mem::paging::FrameAllocator
    where
        Self: 'a;

    fn with_page_table<R>(
        &self,
        f: impl FnMut(&mut Self::PageTable<'_>, &mut Self::Allocator<'_>) -> R,
    ) -> R;
}
