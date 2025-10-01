use core::marker::PhantomData;

use x86_64::structures::paging::{
    PageTableFlags,
    page_table::{PageTable, PageTableEntry},
};

use crate::mem::addr::{Addr, MemPerm, Page, PageSize, PhysAddr, VirtAddr, VirtIntoPtr};
use crate::mem::paging::{
    FrameAllocator, MapError, PageTableOps, PhysMapper, TranslationError, UnmapError,
};

const ENTRY_MASK: usize = 0x1FF;
const PAGE_SHIFT: usize = 12;
const LEVEL_STRIDE: usize = 9;
const TABLE_LEVELS: usize = 4;
const P4_SHIFT: usize = PAGE_SHIFT + 3 * LEVEL_STRIDE;
const P3_SHIFT: usize = PAGE_SHIFT + 2 * LEVEL_STRIDE;
const P2_SHIFT: usize = PAGE_SHIFT + LEVEL_STRIDE;

fn indices_for(addr: VirtAddr) -> [usize; TABLE_LEVELS] {
    let raw = addr.as_raw();
    [
        (raw >> P4_SHIFT) & ENTRY_MASK,
        (raw >> P3_SHIFT) & ENTRY_MASK,
        (raw >> P2_SHIFT) & ENTRY_MASK,
        (raw >> PAGE_SHIFT) & ENTRY_MASK,
    ]
}

fn perm_to_flags(perms: MemPerm) -> PageTableFlags {
    let mut flags = PageTableFlags::PRESENT;
    if perms.is_writable() {
        flags |= PageTableFlags::WRITABLE;
    }
    if perms.is_user_accessible() {
        flags |= PageTableFlags::USER_ACCESSIBLE;
    }
    if !perms.is_executable() {
        flags |= PageTableFlags::NO_EXECUTE;
    }
    flags
}

fn table_flags(perms: MemPerm) -> PageTableFlags {
    let mut flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    if perms.is_user_accessible() {
        flags |= PageTableFlags::USER_ACCESSIBLE;
    }
    flags
}

/// x86_64 page table implementation that relies on a [`PhysMapper`] to touch page table pages.
///
/// # Safety
///
/// The caller must ensure that `root_frame` is uniquely owned for the lifetime of this instance and
/// that `mapper` provides exclusive access to the backing physical memory whenever `phys_to_virt`
/// is used. The constructor zeroes the root table to guarantee a clean slate.
pub struct X86PageTable<M: PhysMapper> {
    mapper: M,
    root_frame: Page<PhysAddr>,
    root_virt: VirtAddr,
    _marker: PhantomData<*mut PageTable>,
}

impl<M: PhysMapper> X86PageTable<M> {
    /// Create a new instance from a root page table frame.
    ///
    /// # Safety
    ///
    /// The caller must uphold the same guarantees described on [`X86PageTable`].
    pub unsafe fn new(root_frame: Page<PhysAddr>, mapper: M) -> Self {
        let root_virt = unsafe { mapper.phys_to_virt(root_frame.start) };
        let table_ptr = root_virt.into_mut_ptr() as *mut PageTable;
        unsafe {
            table_ptr.write(PageTable::new());
        }
        Self {
            mapper,
            root_frame,
            root_virt,
            _marker: PhantomData,
        }
    }

    fn root_table_mut(&mut self) -> &mut PageTable {
        unsafe { &mut *(self.root_virt.into_mut_ptr() as *mut PageTable) }
    }

    fn root_table(&self) -> &PageTable {
        unsafe { &*(self.root_virt.into_ptr() as *const PageTable) }
    }

    fn flush_page(&self, addr: VirtAddr) {
        x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(addr.as_raw() as u64));
    }

    /// # Safety
    ///
    /// Caller must ensure the returned table is not aliased elsewhere and that `phys` points to a
    /// valid page table frame accessible through the active [`PhysMapper`].
    unsafe fn table_from_phys_mut(&mut self, phys: PhysAddr) -> &mut PageTable {
        let virt = unsafe { self.mapper.phys_to_virt(phys) };
        unsafe { &mut *(virt.into_mut_ptr() as *mut PageTable) }
    }

    /// # Safety
    ///
    /// Caller must guarantee `phys` references a valid page table that remains accessible for the
    /// lifetime of the returned reference.
    unsafe fn table_from_phys(&self, phys: PhysAddr) -> &PageTable {
        let virt = unsafe { self.mapper.phys_to_virt(phys) };
        unsafe { &*(virt.into_ptr() as *const PageTable) }
    }

    fn ensure_present<A: FrameAllocator>(
        &mut self,
        entry: &mut PageTableEntry,
        perms: MemPerm,
        allocator: &mut A,
    ) -> Result<&mut PageTable, MapError> {
        if entry.is_unused() {
            let frame = allocator
                .allocate(PageSize::SIZE_4K)
                .ok_or(MapError::FrameAllocationFailed)?;
            let table = unsafe {
                let table = self.table_from_phys_mut(frame.start);
                table.zero();
                table
            };
            entry.set_addr(
                x86_64::PhysAddr::new(frame.start.as_raw()),
                table_flags(perms),
            );
            Ok(table)
        } else {
            let flags = entry.flags();
            if flags.contains(PageTableFlags::HUGE_PAGE) {
                return Err(MapError::InternalError);
            }
            if perms.is_user_accessible() && !flags.contains(PageTableFlags::USER_ACCESSIBLE) {
                entry.set_flags(flags | PageTableFlags::USER_ACCESSIBLE);
            }
            let next_phys = PhysAddr::new(entry.addr().as_u64());
            Ok(unsafe { self.table_from_phys_mut(next_phys) })
        }
    }

    fn walk<A: FrameAllocator>(
        &mut self,
        page: Page<VirtAddr>,
        perms: MemPerm,
        allocator: &mut A,
    ) -> Result<&mut PageTableEntry, MapError> {
        if page.size != PageSize::SIZE_4K {
            return Err(MapError::UnsupportedPageSize(page.size));
        }

        let indices = indices_for(page.start);
        let mut table_ptr = self.root_table_mut() as *mut PageTable;

        for (level, &idx) in indices.iter().enumerate() {
            unsafe {
                let table = &mut *table_ptr;
                if level == TABLE_LEVELS - 1 {
                    return Ok(&mut table[idx]);
                }

                let entry = &mut table[idx];
                table_ptr = self.ensure_present(entry, perms, allocator)? as *mut PageTable;
            }
        }

        Err(MapError::InternalError)
    }

    fn walk_existing_mut(&mut self, page: Page<VirtAddr>) -> Result<&mut PageTableEntry, MapError> {
        if page.size != PageSize::SIZE_4K {
            return Err(MapError::UnsupportedPageSize(page.size));
        }

        let indices = indices_for(page.start);
        let mut table_ptr = self.root_table_mut() as *mut PageTable;

        for (level, &idx) in indices.iter().enumerate() {
            unsafe {
                let table = &mut *table_ptr;
                let entry = &mut table[idx];
                if !entry.flags().contains(PageTableFlags::PRESENT) {
                    return Err(MapError::NotMapped);
                }
                if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                    return Err(MapError::InternalError);
                }

                if level == TABLE_LEVELS - 1 {
                    return Ok(entry);
                }

                let next_phys = PhysAddr::new(entry.addr().as_u64());
                table_ptr = self.table_from_phys_mut(next_phys) as *mut PageTable;
            }
        }

        Err(MapError::InternalError)
    }

    fn walk_for_translation(
        &self,
        addr: VirtAddr,
    ) -> Result<(&PageTableEntry, usize), TranslationError> {
        let indices = indices_for(addr);
        let mut table = self.root_table();

        for (level, &idx) in indices.iter().enumerate() {
            let entry = &table[idx];
            if !entry.flags().contains(PageTableFlags::PRESENT) {
                return Err(TranslationError::NotMapped);
            }

            if level == TABLE_LEVELS - 1 {
                return Ok((entry, addr.as_raw() & ((1 << PAGE_SHIFT) - 1)));
            }

            if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                return Err(TranslationError::HugePage);
            }

            let next_phys = PhysAddr::new(entry.addr().as_u64());
            table = unsafe { self.table_from_phys(next_phys) };
        }

        Err(TranslationError::NotMapped)
    }
}

impl<M: PhysMapper> PageTableOps for X86PageTable<M> {
    fn map<A: FrameAllocator>(
        &mut self,
        page: Page<VirtAddr>,
        frame: Page<PhysAddr>,
        perms: MemPerm,
        allocator: &mut A,
    ) -> Result<(), MapError> {
        if frame.size != PageSize::SIZE_4K {
            return Err(MapError::UnsupportedPageSize(frame.size));
        }
        if !frame.start.is_aligned(PageSize::SIZE_4K.bytes()) {
            return Err(MapError::MisalignedFrame);
        }

        let entry = self.walk(page, perms, allocator)?;
        if !entry.is_unused() {
            return Err(MapError::AlreadyMapped);
        }
        entry.set_addr(
            x86_64::PhysAddr::new(frame.start.as_raw()),
            perm_to_flags(perms),
        );
        self.flush_page(page.start);
        Ok(())
    }

    fn unmap(&mut self, page: Page<VirtAddr>) -> Result<Page<PhysAddr>, UnmapError> {
        if page.size != PageSize::SIZE_4K {
            return Err(UnmapError::UnsupportedPageSize(page.size));
        }

        let indices = indices_for(page.start);
        let mut table_ptr = self.root_table_mut() as *mut PageTable;

        for (level, &idx) in indices.iter().enumerate() {
            let table = unsafe { &mut *table_ptr };
            let entry = &mut table[idx];
            if !entry.flags().contains(PageTableFlags::PRESENT) {
                return Err(UnmapError::NotMapped);
            }

            if level == TABLE_LEVELS - 1 {
                if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                    return Err(UnmapError::HugePage);
                }
                let phys = PhysAddr::new(entry.addr().as_u64());
                entry.set_unused();
                self.flush_page(page.start);
                return Ok(Page::new(phys, PageSize::SIZE_4K));
            }

            if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                return Err(UnmapError::HugePage);
            }

            let next_phys = PhysAddr::new(entry.addr().as_u64());
            table_ptr = unsafe { self.table_from_phys_mut(next_phys) } as *mut PageTable;
        }

        Err(UnmapError::NotMapped)
    }

    fn translate(&self, addr: VirtAddr) -> Result<PhysAddr, TranslationError> {
        let (entry, offset) = self.walk_for_translation(addr)?;
        let base = entry.addr().as_u64();
        Ok(PhysAddr::new(base + offset as u64))
    }

    fn update_permissions(&mut self, page: Page<VirtAddr>, perms: MemPerm) -> Result<(), MapError> {
        let entry = self.walk_existing_mut(page)?;
        let old_flags = entry.flags();
        let preserved = old_flags
            & !(PageTableFlags::WRITABLE
                | PageTableFlags::USER_ACCESSIBLE
                | PageTableFlags::NO_EXECUTE);
        entry.set_flags(preserved | perm_to_flags(perms));
        self.flush_page(page.start);
        Ok(())
    }

    fn root(&self) -> Page<PhysAddr> {
        self.root_frame
    }
}

#[cfg(test)]
mod tests {
    use crate::mem::addr::{MemPerm, Page, PageSize, PhysAddr, VirtAddr, VirtIntoPtr};
    use crate::mem::paging::{
        FrameAllocator, MapError, PageTableOps, PhysMapper, TranslationError,
    };
    use crate::test::kernel_test_case;

    use super::X86PageTable;
    use super::{TABLE_LEVELS, indices_for};
    use x86_64::structures::paging::{PageTableFlags, page_table::PageTable};

    const FRAME_COUNT: usize = 128;
    const FRAME_SIZE: usize = 4096;
    #[repr(align(4096))]
    struct TestMemory([u8; FRAME_COUNT * FRAME_SIZE]);

    /// Backing store for the fake physical memory used in paging tests.
    ///
    /// # Safety
    ///
    /// Tests run single-threaded, so taking mutable references to this static is safe here.
    static mut MEMORY: TestMemory = TestMemory([0; FRAME_COUNT * FRAME_SIZE]);

    unsafe fn memory_base() -> usize {
        unsafe { core::ptr::addr_of!(MEMORY.0) as usize }
    }

    struct TestMapper {
        base: usize,
    }

    impl TestMapper {
        fn new() -> Self {
            let base = unsafe { memory_base() };
            Self { base }
        }
    }

    impl PhysMapper for TestMapper {
        unsafe fn phys_to_virt(&self, addr: PhysAddr) -> VirtAddr {
            VirtAddr::new(self.base + addr.as_raw() as usize)
        }

        fn virt_to_phys(&self, addr: VirtAddr) -> PhysAddr {
            PhysAddr::new((addr.as_raw() - self.base) as u64)
        }
    }

    struct TestAllocator {
        next: usize,
    }

    impl TestAllocator {
        const fn new() -> Self {
            Self { next: 0 }
        }
    }

    impl FrameAllocator for TestAllocator {
        fn allocate(&mut self, size: PageSize) -> Option<Page<PhysAddr>> {
            if size != PageSize::SIZE_4K {
                return None;
            }
            if self.next >= FRAME_COUNT {
                return None;
            }
            let phys = PhysAddr::new((self.next * FRAME_SIZE) as u64);
            self.next += 1;
            Some(Page::new(phys, PageSize::SIZE_4K))
        }
    }

    fn setup() -> (X86PageTable<TestMapper>, TestAllocator) {
        // SAFETY: Paging tests do not run concurrently.
        unsafe {
            core::ptr::write_bytes(
                core::ptr::addr_of_mut!(MEMORY.0) as *mut u8,
                0,
                FRAME_COUNT * FRAME_SIZE,
            );
        }

        let mut allocator = TestAllocator::new();
        let root = allocator
            .allocate(PageSize::SIZE_4K)
            .expect("root frame allocation");
        let mapper = TestMapper::new();
        let table = unsafe { X86PageTable::new(root, mapper) };
        (table, allocator)
    }

    fn phys_slice(offset: PhysAddr, len: usize, mapper: &TestMapper) -> &'static mut [u8] {
        unsafe {
            let virt = mapper.phys_to_virt(offset);
            core::slice::from_raw_parts_mut(virt.into_mut_ptr(), len)
        }
    }

    #[kernel_test_case]
    fn map_and_translate() {
        let (mut table, mut allocator) = setup();
        let mapper = TestMapper::new();

        let virt = VirtAddr::new(0x4000_0000);
        let page = Page::new(virt, PageSize::SIZE_4K);
        let frame = allocator
            .allocate(PageSize::SIZE_4K)
            .expect("payload frame");

        table
            .map(page, frame, MemPerm::KERNEL_RW, &mut allocator)
            .expect("map page");

        let translated = table.translate(virt).expect("translate mapped addr");
        assert_eq!(translated.as_raw(), frame.start.as_raw());

        let payload = phys_slice(frame.start, 8, &mapper);
        payload.copy_from_slice(&0xA5A5A5A5A5A5A5A5u64.to_ne_bytes());

        let resolved = table.translate(virt).expect("translate after write");
        let mirror = phys_slice(resolved, 8, &mapper);
        assert_eq!(mirror, payload);
    }

    #[kernel_test_case]
    fn translate_unmapped() {
        let (table, _allocator) = setup();
        let virt = VirtAddr::new(0x5000_1000);
        let result = table.translate(virt);
        assert_eq!(result, Err(TranslationError::NotMapped));
    }

    #[kernel_test_case]
    fn unmap_page() {
        let (mut table, mut allocator) = setup();

        let virt = VirtAddr::new(0x4000_0000);
        let page = Page::new(virt, PageSize::SIZE_4K);
        let frame = allocator
            .allocate(PageSize::SIZE_4K)
            .expect("payload frame");

        table
            .map(page, frame, MemPerm::KERNEL_RW, &mut allocator)
            .expect("map page");

        let unmapped = table.unmap(page).expect("unmap page");
        assert_eq!(unmapped.start.as_raw(), frame.start.as_raw());

        let result = table.translate(virt);
        assert_eq!(result, Err(TranslationError::NotMapped));
    }

    #[kernel_test_case]
    fn double_map_error() {
        let (mut table, mut allocator) = setup();
        let virt = VirtAddr::new(0x4000_0000);
        let page = Page::new(virt, PageSize::SIZE_4K);
        let frame_a = allocator
            .allocate(PageSize::SIZE_4K)
            .expect("payload frame a");
        let frame_b = allocator
            .allocate(PageSize::SIZE_4K)
            .expect("payload frame b");

        table
            .map(page, frame_a, MemPerm::KERNEL_RW, &mut allocator)
            .expect("map first");

        let result = table.map(page, frame_b, MemPerm::KERNEL_RW, &mut allocator);
        assert!(matches!(result, Err(MapError::AlreadyMapped)));
    }

    #[kernel_test_case]
    fn update_permissions() {
        let (mut table, mut allocator) = setup();
        let mapper = TestMapper::new();

        let virt = VirtAddr::new(0x4000_2000);
        let page = Page::new(virt, PageSize::SIZE_4K);
        let frame = allocator
            .allocate(PageSize::SIZE_4K)
            .expect("payload frame");

        table
            .map(page, frame, MemPerm::USER_RW, &mut allocator)
            .expect("map initial");

        table
            .update_permissions(page, MemPerm::USER_RX)
            .expect("update perms");

        let mut current = table.root().start;
        let indices = indices_for(page.start);

        for (level, &idx) in indices.iter().enumerate() {
            let virt_table = unsafe { mapper.phys_to_virt(current) };
            let table_ref = unsafe { &*(virt_table.into_ptr() as *const PageTable) };
            let entry = &table_ref[idx];

            if level == TABLE_LEVELS - 1 {
                let flags = entry.flags();
                assert!(!flags.contains(PageTableFlags::WRITABLE));
                assert!(flags.contains(PageTableFlags::USER_ACCESSIBLE));
                assert!(!flags.contains(PageTableFlags::NO_EXECUTE));
                break;
            }

            current = PhysAddr::new(entry.addr().as_u64());
        }
    }
}
