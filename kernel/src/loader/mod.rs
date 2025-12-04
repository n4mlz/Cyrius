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

/// Platform-specific hooks required by the Linux ELF loader.
pub trait LinuxElfPlatform {
    type AddressSpace: AddressSpaceExt;
    type UserStack;

    fn machine_id() -> u16;
    fn page_size() -> usize;
    fn allocate_user_stack(
        space: &Self::AddressSpace,
        size: usize,
    ) -> Result<Self::UserStack, crate::arch::api::UserStackError>;
    fn user_stack_top(stack: &Self::UserStack) -> crate::mem::addr::VirtAddr;
}

#[cfg(target_arch = "x86_64")]
pub type DefaultLinuxElfPlatform = crate::arch::x86_64::loader::X86LinuxElfPlatform;
