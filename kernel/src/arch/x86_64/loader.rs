use crate::loader::AddressSpaceExt;

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
