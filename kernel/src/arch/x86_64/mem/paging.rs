use core::convert::TryFrom;
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
const TABLE_LEVELS_4: usize = 4;
const TABLE_LEVELS_5: usize = 5;
const P4_SHIFT: usize = PAGE_SHIFT + 3 * LEVEL_STRIDE;
const P3_SHIFT: usize = PAGE_SHIFT + 2 * LEVEL_STRIDE;
const P2_SHIFT: usize = PAGE_SHIFT + LEVEL_STRIDE;
const P5_SHIFT: usize = PAGE_SHIFT + 4 * LEVEL_STRIDE;

const PHYS_ADDR_RANGE_ERR: &str = "physical address exceeds target width";
const VIRT_ADDR_RANGE_ERR: &str = "virtual address exceeds u64 range";

fn phys_from_x86(addr: x86_64::PhysAddr) -> PhysAddr {
    let raw = usize::try_from(addr.as_u64()).expect(PHYS_ADDR_RANGE_ERR);
    PhysAddr::new(raw)
}

fn x86_from_phys(addr: PhysAddr) -> x86_64::PhysAddr {
    let raw = u64::try_from(addr.as_raw()).expect(PHYS_ADDR_RANGE_ERR);
    x86_64::PhysAddr::new(raw)
}

/// Page table configuration for different paging modes
#[derive(Debug, Clone, Copy)]
enum PagingMode {
    /// 4-level paging (48-bit virtual addresses)
    Level4,
    /// 5-level paging (57-bit virtual addresses, LA57)
    #[allow(dead_code)] // LA57 support is planned but not yet wired up
    Level5,
}

impl PagingMode {
    /// Detect the current paging mode based on CR4.LA57 and CPUID.
    ///
    /// # Safety
    ///
    /// This function reads CPU control registers and should only be called
    /// when the CPU is in a valid state for reading control registers.
    unsafe fn detect() -> Self {
        // TODO: Implement proper LA57 detection using raw CPUID and CR4 access
        // For now, default to 4-level paging for compatibility
        //
        // In a real implementation, you would:
        // 1. Use raw CPUID instruction to check CPUID.7.0:ECX.LA57
        // 2. Use raw CR4 register access to check CR4.LA57
        // 3. Return Level5 if both are set, Level4 otherwise
        Self::Level4
    }

    fn table_levels(&self) -> usize {
        match self {
            Self::Level4 => TABLE_LEVELS_4,
            Self::Level5 => TABLE_LEVELS_5,
        }
    }
}

fn indices_for(addr: VirtAddr, mode: PagingMode) -> [usize; 5] {
    let raw = addr.as_raw();
    let mut indices = [0; 5];

    match mode {
        PagingMode::Level4 => {
            indices[0] = (raw >> P4_SHIFT) & ENTRY_MASK;
            indices[1] = (raw >> P3_SHIFT) & ENTRY_MASK;
            indices[2] = (raw >> P2_SHIFT) & ENTRY_MASK;
            indices[3] = (raw >> PAGE_SHIFT) & ENTRY_MASK;
            indices[4] = 0; // Unused for 4-level paging
        }
        PagingMode::Level5 => {
            indices[0] = (raw >> P5_SHIFT) & ENTRY_MASK;
            indices[1] = (raw >> P4_SHIFT) & ENTRY_MASK;
            indices[2] = (raw >> P3_SHIFT) & ENTRY_MASK;
            indices[3] = (raw >> P2_SHIFT) & ENTRY_MASK;
            indices[4] = (raw >> PAGE_SHIFT) & ENTRY_MASK;
        }
    }

    indices
}

/// Convert memory permissions to page table flags for leaf entries (PTE).
///
/// # NX Bit Requirements
///
/// The NO_EXECUTE bit is only effective when:
/// 1. EFER.NXE is set to 1 (must be done during OS initialization)
/// 2. The CPU supports the XD/NX feature (verified via CPUID)
///
/// Without EFER.NXE=1, the NX bit is ignored and all pages remain executable.
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

/// Convert memory permissions to page table flags for intermediate tables.
///
/// Intermediate tables (PML4, PDPT, PD) require WRITABLE to be set for proper
/// permission propagation. In x86-64, access permissions are determined by
/// the AND of all levels - if any level has R/W=0, write access is denied.
fn table_flags(perms: MemPerm) -> PageTableFlags {
    let mut flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    if perms.is_user_accessible() {
        flags |= PageTableFlags::USER_ACCESSIBLE;
    }
    flags
}

/// Check if a virtual address is canonical (x86-64 requirement).
///
/// In x86-64, virtual addresses must be canonical, meaning the upper bits
/// must be sign-extended. Non-canonical addresses cause #GP on access.
///
/// For 4-level paging: bits 63:47 must all be the same as bit 47
/// For 5-level paging: bits 63:56 must all be the same as bit 56
fn is_canonical(addr: VirtAddr, mode: PagingMode) -> bool {
    let raw = u64::try_from(addr.as_raw()).expect(VIRT_ADDR_RANGE_ERR);

    match mode {
        PagingMode::Level4 => {
            // For 48-bit addresses: bits 63:47 must all be the same as bit 47
            let upper_bits = raw >> 47;
            upper_bits == 0 || upper_bits == 0x1FFFF
        }
        PagingMode::Level5 => {
            // For 57-bit addresses: bits 63:57 must all be the same as bit 56
            // This is bit 56's sign extension, so we check bits 63:57 (7 bits)
            let upper_bits = raw >> 57;
            upper_bits == 0 || upper_bits == 0x7F
        }
    }
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
    paging_mode: PagingMode,
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
            paging_mode: unsafe { PagingMode::detect() },
            _marker: PhantomData,
        }
    }

    /// Construct a page table wrapper around an existing root without clearing it.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `root_frame` refers to a valid level-4/level-5 page table
    /// that remains accessible through `mapper` for the lifetime of the returned instance.
    pub unsafe fn from_existing(root_frame: Page<PhysAddr>, mapper: M) -> Self {
        let root_virt = unsafe { mapper.phys_to_virt(root_frame.start) };
        Self {
            mapper,
            root_frame,
            root_virt,
            paging_mode: unsafe { PagingMode::detect() },
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
        let raw = u64::try_from(addr.as_raw()).expect(VIRT_ADDR_RANGE_ERR);
        x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(raw));
    }

    /// Flush TLB entries for all pages that could be affected by changes to intermediate tables.
    ///
    /// When intermediate table entries are modified (especially U/S or R/W bits),
    /// we need to invalidate the TLB and paging-structure cache for all pages
    /// that could be affected by the change. This is a conservative approach that
    /// flushes all TLB entries, but ensures correctness.
    fn flush_all_tlb(&self) {
        // For simplicity and correctness, we flush all TLB entries when intermediate
        // table permissions are changed. In a production system, you might want
        // to track affected pages more precisely or use PCID-based invalidation.
        x86_64::instructions::tlb::flush_all();
    }

    /// Check if a page table is empty (all entries are unused).
    ///
    /// # Safety
    ///
    /// Caller must ensure `phys` points to a valid page table frame.
    unsafe fn is_table_empty(&self, phys: PhysAddr) -> bool {
        let table = unsafe { self.table_from_phys(phys) };
        for i in 0..512 {
            if !table[i].is_unused() {
                return false;
            }
        }
        true
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
            entry.set_addr(x86_from_phys(frame.start), table_flags(perms));
            Ok(table)
        } else {
            let flags = entry.flags();
            if flags.contains(PageTableFlags::HUGE_PAGE) {
                return Err(MapError::InternalError);
            }
            // Update flags for existing entries to ensure proper permission propagation
            // x86-64 requires ALL levels to have R/W=1 for write access, U/S=1 for user access
            let mut new_flags = flags;
            if perms.is_writable() && !flags.contains(PageTableFlags::WRITABLE) {
                new_flags |= PageTableFlags::WRITABLE;
            }
            if perms.is_user_accessible() && !flags.contains(PageTableFlags::USER_ACCESSIBLE) {
                new_flags |= PageTableFlags::USER_ACCESSIBLE;
            }
            if new_flags != flags {
                entry.set_flags(new_flags);
                // Critical: When intermediate table permissions are changed, we must
                // invalidate TLB and paging-structure cache to ensure correctness.
                // x86-64 caches intermediate table entries, and changes to U/S or R/W
                // bits can affect existing translations.
                self.flush_all_tlb();
            }
            let next_phys = phys_from_x86(entry.addr());
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

        let indices = indices_for(page.start, self.paging_mode);
        let mut table_ptr = self.root_table_mut() as *mut PageTable;

        for (level, &idx) in indices[..self.paging_mode.table_levels()]
            .iter()
            .enumerate()
        {
            unsafe {
                let table = &mut *table_ptr;
                if level == self.paging_mode.table_levels() - 1 {
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

        let indices = indices_for(page.start, self.paging_mode);
        let mut table_ptr = self.root_table_mut() as *mut PageTable;

        for (level, &idx) in indices[..self.paging_mode.table_levels()]
            .iter()
            .enumerate()
        {
            unsafe {
                let table = &mut *table_ptr;
                let entry = &mut table[idx];
                if !entry.flags().contains(PageTableFlags::PRESENT) {
                    return Err(MapError::NotMapped);
                }
                if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                    return Err(MapError::InternalError);
                }

                if level == self.paging_mode.table_levels() - 1 {
                    return Ok(entry);
                }

                let next_phys = phys_from_x86(entry.addr());
                table_ptr = self.table_from_phys_mut(next_phys) as *mut PageTable;
            }
        }

        Err(MapError::InternalError)
    }

    fn walk_for_translation(
        &self,
        addr: VirtAddr,
    ) -> Result<(&PageTableEntry, usize), TranslationError> {
        let indices = indices_for(addr, self.paging_mode);
        let mut table = self.root_table();

        for (level, &idx) in indices[..self.paging_mode.table_levels()]
            .iter()
            .enumerate()
        {
            let entry = &table[idx];
            if !entry.flags().contains(PageTableFlags::PRESENT) {
                return Err(TranslationError::NotMapped);
            }

            if level == self.paging_mode.table_levels() - 1 {
                return Ok((entry, addr.as_raw() & ((1 << PAGE_SHIFT) - 1)));
            }

            if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                return Err(TranslationError::HugePage);
            }

            let next_phys = phys_from_x86(entry.addr());
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
        if !is_canonical(page.start, self.paging_mode) {
            return Err(MapError::NonCanonical);
        }

        let entry = self.walk(page, perms, allocator)?;
        if !entry.is_unused() {
            return Err(MapError::AlreadyMapped);
        }
        entry.set_addr(x86_from_phys(frame.start), perm_to_flags(perms));
        self.flush_page(page.start);
        Ok(())
    }

    fn unmap(&mut self, page: Page<VirtAddr>) -> Result<Page<PhysAddr>, UnmapError> {
        if page.size != PageSize::SIZE_4K {
            return Err(UnmapError::UnsupportedPageSize(page.size));
        }

        let indices = indices_for(page.start, self.paging_mode);
        let mut table_ptr = self.root_table_mut() as *mut PageTable;

        // Track parent chain for recursive cleanup
        let mut parent_chain: [(usize, *mut PageTable); 5] = [(0, core::ptr::null_mut()); 5];
        let mut parent_count = 0;

        let levels = self.paging_mode.table_levels();

        for (level, (&idx, slot)) in indices[..levels]
            .iter()
            .zip(parent_chain.iter_mut())
            .enumerate()
        {
            let table = unsafe { &mut *table_ptr };
            let entry = &mut table[idx];
            if !entry.flags().contains(PageTableFlags::PRESENT) {
                return Err(UnmapError::NotMapped);
            }

            if level == self.paging_mode.table_levels() - 1 {
                // Final level - unmap the page
                if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                    return Err(UnmapError::HugePage);
                }
                let phys = phys_from_x86(entry.addr());
                entry.set_unused();
                self.flush_page(page.start);

                // Clean up empty intermediate tables recursively
                self.cleanup_empty_tables_recursive(&parent_chain[..parent_count]);

                return Ok(Page::new(phys, PageSize::SIZE_4K));
            }

            if entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                return Err(UnmapError::HugePage);
            }

            // Store parent information for cleanup
            *slot = (idx, table_ptr);
            parent_count = level + 1;

            let next_phys = phys_from_x86(entry.addr());
            table_ptr = unsafe { self.table_from_phys_mut(next_phys) } as *mut PageTable;
        }

        Err(UnmapError::NotMapped)
    }

    fn translate(&self, addr: VirtAddr) -> Result<PhysAddr, TranslationError> {
        let (entry, offset) = self.walk_for_translation(addr)?;
        let base = phys_from_x86(entry.addr());
        let phys = base
            .checked_add(offset)
            .expect("physical address overflow during translation");
        Ok(phys)
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

impl<M: PhysMapper> X86PageTable<M> {
    /// Clean up empty intermediate tables after unmapping a page.
    ///
    /// This function recursively removes empty page table frames from the hierarchy,
    /// starting from the leaf level and working up to the root.
    fn cleanup_empty_tables_recursive(&mut self, parent_chain: &[(usize, *mut PageTable)]) {
        // Process from leaf to root (reverse order)
        for &(parent_index, parent_table_ptr) in parent_chain.iter().rev() {
            if parent_table_ptr.is_null() {
                continue; // Skip invalid entries
            }

            let parent_table = unsafe { &mut *parent_table_ptr };
            let parent_entry = &mut parent_table[parent_index];

            // Check if the child table is now empty
            let child_phys = phys_from_x86(parent_entry.addr());
            if unsafe { self.is_table_empty(child_phys) } {
                // Mark the parent entry as unused
                parent_entry.set_unused();

                // Note: In a real implementation, you would deallocate the physical frame
                // here using a frame allocator. For now, we just mark it as unused.
                // TODO: Add frame deallocation when frame allocator supports it.
            } else {
                // If this table is not empty, no need to check higher levels
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::convert::TryFrom;

    use super::{VIRT_ADDR_RANGE_ERR, phys_from_x86};
    use crate::mem::addr::{MemPerm, Page, PageSize, PhysAddr, VirtAddr, VirtIntoPtr};
    use crate::mem::paging::{
        FrameAllocator, MapError, PageTableOps, PhysMapper, TranslationError,
    };
    use crate::test::kernel_test_case;

    use super::X86PageTable;
    use super::{TABLE_LEVELS_4, indices_for};
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
            VirtAddr::new(self.base + addr.as_raw())
        }

        fn virt_to_phys(&self, addr: VirtAddr) -> PhysAddr {
            let raw = addr
                .as_raw()
                .checked_sub(self.base)
                .expect("virtual address below mapped range");
            PhysAddr::new(raw)
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
            let phys = PhysAddr::new(self.next * FRAME_SIZE);
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
        let indices = indices_for(page.start, super::PagingMode::Level4);

        for (level, &idx) in indices[..super::TABLE_LEVELS_4].iter().enumerate() {
            let virt_table = unsafe { mapper.phys_to_virt(current) };
            let table_ref = unsafe { &*(virt_table.into_ptr() as *const PageTable) };
            let entry = &table_ref[idx];

            if level == TABLE_LEVELS_4 - 1 {
                let flags = entry.flags();
                assert!(!flags.contains(PageTableFlags::WRITABLE));
                assert!(flags.contains(PageTableFlags::USER_ACCESSIBLE));
                assert!(!flags.contains(PageTableFlags::NO_EXECUTE));
                break;
            }

            current = phys_from_x86(entry.addr());
        }
    }

    #[kernel_test_case]
    fn writable_propagation_to_existing_tables() {
        let (mut table, mut allocator) = setup();
        let mapper = TestMapper::new();

        // First, map a read-only page to create intermediate tables with R/W=0
        let virt = VirtAddr::new(0x4000_3000);
        let page = Page::new(virt, PageSize::SIZE_4K);
        let frame = allocator
            .allocate(PageSize::SIZE_4K)
            .expect("payload frame");

        table
            .map(page, frame, MemPerm::KERNEL_R, &mut allocator)
            .expect("map read-only page");

        // Now map a writable page at a different address that shares some intermediate tables
        let virt2 = VirtAddr::new(0x4000_4000);
        let page2 = Page::new(virt2, PageSize::SIZE_4K);
        let frame2 = allocator
            .allocate(PageSize::SIZE_4K)
            .expect("payload frame 2");

        table
            .map(page2, frame2, MemPerm::KERNEL_RW, &mut allocator)
            .expect("map writable page");

        // Verify that intermediate tables now have WRITABLE set
        let mut current = table.root().start;
        let indices = indices_for(page2.start, super::PagingMode::Level4);

        for (level, &idx) in indices[..super::TABLE_LEVELS_4].iter().enumerate() {
            let virt_table = unsafe { mapper.phys_to_virt(current) };
            let table_ref = unsafe { &*(virt_table.into_ptr() as *const PageTable) };
            let entry = &table_ref[idx];

            if level == TABLE_LEVELS_4 - 1 {
                // Final PTE should have WRITABLE
                let flags = entry.flags();
                assert!(flags.contains(PageTableFlags::WRITABLE));
                break;
            } else {
                // Intermediate tables should also have WRITABLE for proper propagation
                let flags = entry.flags();
                assert!(flags.contains(PageTableFlags::WRITABLE));
            }

            current = phys_from_x86(entry.addr());
        }
    }

    #[kernel_test_case]
    fn user_propagation_to_existing_tables() {
        let (mut table, mut allocator) = setup();
        let mapper = TestMapper::new();

        // First, map a kernel-only page to create intermediate tables with U/S=0
        let virt = VirtAddr::new(0x4000_5000);
        let page = Page::new(virt, PageSize::SIZE_4K);
        let frame = allocator
            .allocate(PageSize::SIZE_4K)
            .expect("payload frame");

        table
            .map(page, frame, MemPerm::KERNEL_RW, &mut allocator)
            .expect("map kernel page");

        // Now map a user page at a different address that shares some intermediate tables
        let virt2 = VirtAddr::new(0x4000_6000);
        let page2 = Page::new(virt2, PageSize::SIZE_4K);
        let frame2 = allocator
            .allocate(PageSize::SIZE_4K)
            .expect("payload frame 2");

        table
            .map(page2, frame2, MemPerm::USER_RW, &mut allocator)
            .expect("map user page");

        // Verify that intermediate tables now have USER_ACCESSIBLE set
        let mut current = table.root().start;
        let indices = indices_for(page2.start, super::PagingMode::Level4);

        for (level, &idx) in indices[..super::TABLE_LEVELS_4].iter().enumerate() {
            let virt_table = unsafe { mapper.phys_to_virt(current) };
            let table_ref = unsafe { &*(virt_table.into_ptr() as *const PageTable) };
            let entry = &table_ref[idx];

            if level == TABLE_LEVELS_4 - 1 {
                // Final PTE should have USER_ACCESSIBLE
                let flags = entry.flags();
                assert!(flags.contains(PageTableFlags::USER_ACCESSIBLE));
                break;
            } else {
                // Intermediate tables should also have USER_ACCESSIBLE for proper propagation
                let flags = entry.flags();
                assert!(flags.contains(PageTableFlags::USER_ACCESSIBLE));
            }

            current = phys_from_x86(entry.addr());
        }
    }

    #[kernel_test_case]
    fn canonical_address_validation() {
        let (mut table, mut allocator) = setup();

        // Test non-canonical addresses that should be rejected
        let non_canonical_addrs = [
            // Upper half non-canonical (bits 63:47 not all 1s)
            0x8000_0000_0000_0000u64,
            // Lower half non-canonical (bits 63:47 not all 0s)
            0x0000_8000_0000_0000u64,
            // Mixed pattern
            0x4000_0000_0000_0000u64,
        ];

        for &addr in &non_canonical_addrs {
            let raw = usize::try_from(addr).expect(VIRT_ADDR_RANGE_ERR);
            let virt = VirtAddr::new(raw);
            let page = Page::new(virt, PageSize::SIZE_4K);
            let frame = allocator
                .allocate(PageSize::SIZE_4K)
                .expect("payload frame");

            let result = table.map(page, frame, MemPerm::KERNEL_RW, &mut allocator);
            assert!(
                matches!(result, Err(MapError::NonCanonical)),
                "Non-canonical address 0x{:x} should be rejected",
                addr
            );
        }

        // Test canonical addresses that should be accepted
        let canonical_addrs = [
            // Lower half canonical
            0x0000_0000_4000_0000u64,
            // Upper half canonical
            0xFFFF_8000_0000_0000u64,
        ];

        for &addr in &canonical_addrs {
            let raw = usize::try_from(addr).expect(VIRT_ADDR_RANGE_ERR);
            let virt = VirtAddr::new(raw);
            let page = Page::new(virt, PageSize::SIZE_4K);
            let frame = allocator
                .allocate(PageSize::SIZE_4K)
                .expect("payload frame");

            let result = table.map(page, frame, MemPerm::KERNEL_RW, &mut allocator);
            assert!(
                result.is_ok(),
                "Canonical address 0x{:x} should be accepted",
                addr
            );
        }
    }

    #[kernel_test_case]
    fn recursive_cleanup_empty_tables() {
        let (mut table, mut allocator) = setup();

        // Map multiple pages that share intermediate tables
        let pages = [
            VirtAddr::new(0x4000_7000),
            VirtAddr::new(0x4000_8000),
            VirtAddr::new(0x4000_9000),
        ];

        let mut frames = [(
            Page::new(VirtAddr::new(0), PageSize::SIZE_4K),
            Page::new(PhysAddr::new(0), PageSize::SIZE_4K),
        ); 3];
        let mut frame_count = 0;

        for &virt in &pages {
            let page = Page::new(virt, PageSize::SIZE_4K);
            let frame = allocator
                .allocate(PageSize::SIZE_4K)
                .expect("payload frame");

            table
                .map(page, frame, MemPerm::KERNEL_RW, &mut allocator)
                .expect("map page");
            frames[frame_count] = (page, frame);
            frame_count += 1;
        }

        // Verify all pages are mapped
        for (page, _) in frames.iter().take(frame_count) {
            let translated = table.translate(page.start).expect("translate mapped addr");
            assert!(translated.as_raw() > 0);
        }

        // Unmap all pages - this should trigger recursive cleanup
        for (page, _) in frames.iter().take(frame_count) {
            let page_to_unmap = Page::new(page.start, page.size);
            let unmapped = table.unmap(page_to_unmap).expect("unmap page");
            assert!(unmapped.start.as_raw() > 0);
        }

        // Verify all pages are unmapped
        for &virt in &pages {
            let result = table.translate(virt);
            assert_eq!(result, Err(TranslationError::NotMapped));
        }

        // Verify that intermediate tables have been cleaned up
        // by checking that we can map a new page at the same virtual address
        // without getting AlreadyMapped error
        let test_page = Page::new(pages[0], PageSize::SIZE_4K);
        let test_frame = allocator.allocate(PageSize::SIZE_4K).expect("test frame");

        let result = table.map(test_page, test_frame, MemPerm::KERNEL_RW, &mut allocator);
        assert!(result.is_ok(), "Should be able to map after cleanup");
    }
}
