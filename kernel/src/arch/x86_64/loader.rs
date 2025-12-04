use crate::loader::AddressSpaceExt;
use crate::loader::LinuxElfPlatform;
use crate::mem::addr::{PageSize, VirtAddr};

impl AddressSpaceExt for crate::arch::x86_64::thread::AddressSpace {
    type PageTable<'a> =
        crate::arch::x86_64::mem::paging::X86PageTable<crate::mem::mapper::OffsetMapper>;
    type Allocator<'a> = crate::mem::frame::FrameAllocatorGuard<'a>;

    fn with_page_table<R>(
        &self,
        f: impl FnMut(&mut Self::PageTable<'_>, &mut Self::Allocator<'_>) -> R,
    ) -> R {
        let mut f = f;
        self.with_table(|table, allocator| f(table, allocator))
    }
}

pub struct X86LinuxElfPlatform;

impl LinuxElfPlatform for X86LinuxElfPlatform {
    type AddressSpace = crate::arch::x86_64::thread::AddressSpace;
    type UserStack = <crate::arch::x86_64::X86_64 as crate::arch::api::ArchThread>::UserStack;

    fn machine_id() -> u16 {
        0x3E // EM_X86_64
    }

    fn page_size() -> usize {
        PageSize::SIZE_4K.bytes()
    }

    fn allocate_user_stack(
        space: &Self::AddressSpace,
        size: usize,
    ) -> Result<Self::UserStack, crate::arch::api::UserStackError> {
        <crate::arch::x86_64::X86_64 as crate::arch::api::ArchThread>::allocate_user_stack(
            space, size,
        )
    }

    fn user_stack_top(stack: &Self::UserStack) -> VirtAddr {
        <crate::arch::x86_64::X86_64 as crate::arch::api::ArchThread>::user_stack_top(stack)
    }
}
