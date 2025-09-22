use core::arch::asm;
use core::ptr;

use crate::arch::api::{ArchMmu, DirectMapRegion, KernelLayoutRequest, KernelVirtLayout};
use crate::boot::BootInfo;
use crate::mem::addr::{Addr, AddrRange, MemPerm, PageSize, PhysAddr, VirtAddr};
use crate::mem::frame::{BootFrameAllocator, FrameAllocator};
use crate::mem::paging::{MapError, UnmapError};
use crate::util::align_up;
use crate::util::spinlock::SpinLock;

use super::X86BootInfo;

const PAGE_SIZE: usize = 0x1000;
const ENTRIES_PER_TABLE: usize = 512;
const HEAP_VIRT_START: usize = 0xffff_8000_0000_0000;
const DIRECT_MAP_BASE: usize = 0xffff_0000_0000_0000;

const ENTRY_PRESENT: u64 = 1;
const ENTRY_WRITABLE: u64 = 1 << 1;
const ENTRY_USER: u64 = 1 << 2;
const ENTRY_HUGE_PAGE: u64 = 1 << 7;
const ENTRY_NO_EXECUTE: u64 = 1 << 63;
const ENTRY_ADDR_MASK: u64 = 0x000f_ffff_ffff_f000;

pub struct X86Mmu {
    recursive_index: SpinLock<Option<usize>>,
    layout: SpinLock<Option<KernelVirtLayout>>,
}

static MMU: X86Mmu = X86Mmu::new();

impl X86Mmu {
    pub const fn new() -> Self {
        Self {
            recursive_index: SpinLock::new(None),
            layout: SpinLock::new(None),
        }
    }

    pub fn instance() -> &'static Self {
        &MMU
    }

    fn recursive_index(&self) -> Result<usize, MapError> {
        let guard = self.recursive_index.lock();
        guard.ok_or(MapError::Unsupported)
    }

    fn current_layout(&self) -> Option<KernelVirtLayout> {
        *self.layout.lock()
    }

    fn align_heap_region(
        &self,
        region: AddrRange<PhysAddr>,
    ) -> Result<AddrRange<PhysAddr>, MapError> {
        let start = align_up(region.start.as_usize(), PAGE_SIZE).ok_or(MapError::InvalidAddress)?;
        let end = align_down(region.end.as_usize(), PAGE_SIZE);
        if start >= end {
            return Err(MapError::InvalidAddress);
        }
        Ok(AddrRange {
            start: PhysAddr::from_usize(start),
            end: PhysAddr::from_usize(end),
        })
    }

    fn map_range(
        mapper: &RecursiveMapper,
        allocator: &mut dyn FrameAllocator,
        virt_start: usize,
        phys_start: usize,
        length: usize,
        perm: MemPerm,
    ) -> Result<(), MapError> {
        if length == 0 {
            return Ok(());
        }

        if virt_start & (PAGE_SIZE - 1) != 0 || phys_start & (PAGE_SIZE - 1) != 0 {
            return Err(MapError::InvalidAddress);
        }

        if length & (PAGE_SIZE - 1) != 0 {
            return Err(MapError::InvalidAddress);
        }

        let virt_end = virt_start
            .checked_add(length)
            .ok_or(MapError::InvalidAddress)?;
        let phys_end = phys_start
            .checked_add(length)
            .ok_or(MapError::InvalidAddress)?;

        let mut virt = virt_start;
        let mut phys = phys_start;
        while virt < virt_end && phys < phys_end {
            unsafe {
                mapper.map_page(virt, phys, perm, allocator)?;
            }
            virt += PAGE_SIZE;
            phys += PAGE_SIZE;
        }

        Ok(())
    }

    fn map_direct_window(
        &self,
        mapper: &RecursiveMapper,
        allocator: &mut dyn FrameAllocator,
        boot_info: &BootInfo<X86BootInfo>,
    ) -> Result<Option<DirectMapRegion>, MapError> {
        let mut max_end = 0usize;

        for region in boot_info.memory_map.iter() {
            let start = align_down(region.range.start.as_usize(), PAGE_SIZE);
            let end =
                align_up(region.range.end.as_usize(), PAGE_SIZE).ok_or(MapError::InvalidAddress)?;
            if start >= end {
                continue;
            }

            let virt_start = DIRECT_MAP_BASE
                .checked_add(start)
                .ok_or(MapError::InvalidAddress)?;
            let length = end - start;

            Self::map_range(
                mapper,
                allocator,
                virt_start,
                start,
                length,
                MemPerm::KERNEL_RW,
            )?;
            max_end = max_end.max(end);
        }

        if max_end == 0 {
            return Ok(None);
        }

        Ok(Some(DirectMapRegion {
            phys_start: PhysAddr::from_usize(0),
            virt_start: VirtAddr::from_usize(DIRECT_MAP_BASE),
            length: max_end,
        }))
    }
}

impl ArchMmu<X86BootInfo> for X86Mmu {
    fn early_init(&self, boot_info: &BootInfo<X86BootInfo>) -> Result<(), MapError> {
        let mut guard = self.recursive_index.lock();
        if guard.is_none() {
            *guard = boot_info.arch_data.recursive_index.map(|idx| idx as usize);
        }
        guard.ok_or(MapError::Unsupported).map(|_| ())
    }

    fn prepare_kernel_layout(
        &self,
        boot_info: &BootInfo<X86BootInfo>,
        request: KernelLayoutRequest,
    ) -> Result<KernelVirtLayout, MapError> {
        if let Some(layout) = self.current_layout() {
            return Ok(layout);
        }

        let recursive_index = self.recursive_index()?;
        let aligned_heap = self.align_heap_region(request.heap_phys)?;
        let heap_length = aligned_heap.len();

        let heap_virt_start = HEAP_VIRT_START;
        let heap_virt_end = heap_virt_start
            .checked_add(heap_length)
            .ok_or(MapError::InvalidAddress)?;
        let heap_virt = AddrRange {
            start: VirtAddr::from_usize(heap_virt_start),
            end: VirtAddr::from_usize(heap_virt_end),
        };

        let mut allocator =
            BootFrameAllocator::with_reservation_from_boot_info(boot_info, aligned_heap);
        let mapper = RecursiveMapper::new(recursive_index);

        Self::map_range(
            &mapper,
            &mut allocator,
            heap_virt_start,
            aligned_heap.start.as_usize(),
            heap_length,
            MemPerm::KERNEL_RW,
        )?;

        let phys_window = if request.map_phys_window {
            self.map_direct_window(&mapper, &mut allocator, boot_info)?
        } else {
            None
        };

        let layout = KernelVirtLayout {
            heap: heap_virt,
            phys_window,
        };

        let mut guard = self.layout.lock();
        if guard.is_none() {
            *guard = Some(layout);
        }

        Ok(layout)
    }

    fn map(
        &self,
        virt: AddrRange<VirtAddr>,
        phys: AddrRange<PhysAddr>,
        perm: MemPerm,
        allocator: &mut dyn FrameAllocator,
    ) -> Result<(), MapError> {
        let recursive_index = self.recursive_index()?;
        if virt.len() != phys.len() {
            return Err(MapError::InvalidAddress);
        }

        if !virt.start.is_aligned(PAGE_SIZE) || !phys.start.is_aligned(PAGE_SIZE) {
            return Err(MapError::InvalidAddress);
        }

        if virt.len() & (PAGE_SIZE - 1) != 0 {
            return Err(MapError::InvalidAddress);
        }

        let mapper = RecursiveMapper::new(recursive_index);
        Self::map_range(
            &mapper,
            allocator,
            virt.start.as_usize(),
            phys.start.as_usize(),
            phys.len(),
            perm,
        )
    }

    fn unmap(&self, virt: AddrRange<VirtAddr>) -> Result<(), UnmapError> {
        let recursive_index = self
            .recursive_index()
            .map_err(|_| UnmapError::InvalidAddress)?;

        if !virt.start.is_aligned(PAGE_SIZE) || virt.len() & (PAGE_SIZE - 1) != 0 {
            return Err(UnmapError::InvalidAddress);
        }

        let mapper = RecursiveMapper::new(recursive_index);
        let mut offset = 0usize;
        while offset < virt.len() {
            unsafe {
                mapper.unmap_page(virt.start.as_usize() + offset)?;
            }
            offset += PAGE_SIZE;
        }

        Ok(())
    }

    fn phys_to_virt(&self, phys: PhysAddr) -> Option<VirtAddr> {
        let layout = self.current_layout()?;
        let window = layout.phys_window?;
        if !window.contains_phys(phys) {
            return None;
        }

        let offset = phys.as_usize().checked_sub(window.phys_start.as_usize())?;
        if offset >= window.length {
            return None;
        }

        let virt_candidate = window
            .virt_start
            .as_usize()
            .checked_add(offset)
            .map(VirtAddr::from_usize)?;

        let recursive_index = self.recursive_index().ok()?;
        let mapper = RecursiveMapper::new(recursive_index);
        let resolved = unsafe { mapper.translate(virt_candidate.as_usize()) }?;
        (resolved == phys.as_usize()).then_some(virt_candidate)
    }

    fn virt_to_phys(&self, virt: VirtAddr) -> Option<PhysAddr> {
        let recursive_index = self.recursive_index().ok()?;
        let mapper = RecursiveMapper::new(recursive_index);
        unsafe { mapper.translate(virt.as_usize()) }.map(PhysAddr::from_usize)
    }

    fn kernel_layout(&self) -> Option<KernelVirtLayout> {
        self.current_layout()
    }
}

struct RecursiveMapper {
    recursive_index: usize,
}

impl RecursiveMapper {
    fn new(recursive_index: usize) -> Self {
        Self { recursive_index }
    }

    unsafe fn map_page(
        &self,
        virt: usize,
        phys: usize,
        perm: MemPerm,
        allocator: &mut dyn FrameAllocator,
    ) -> Result<(), MapError> {
        let p4_index = (virt >> 39) & 0x1ff;
        let p3_index = (virt >> 30) & 0x1ff;
        let p2_index = (virt >> 21) & 0x1ff;
        let p1_index = (virt >> 12) & 0x1ff;

        let p4 = self.p4_table();
        let p4_entry = unsafe { &mut (*p4).entries[p4_index] };
        if !p4_entry.is_present() {
            let frame = allocator
                .alloc(PageSize::Size4K)
                .ok_or(MapError::OutOfMemory)?;
            p4_entry.set_table(frame.start.as_usize());
            self.zero_table(self.p3_table(p4_index));
        }

        let p3 = self.p3_table(p4_index);
        let p3_entry = unsafe { &mut (*p3).entries[p3_index] };
        if !p3_entry.is_present() {
            let frame = allocator
                .alloc(PageSize::Size4K)
                .ok_or(MapError::OutOfMemory)?;
            p3_entry.set_table(frame.start.as_usize());
            self.zero_table(self.p2_table(p4_index, p3_index));
        } else if p3_entry.is_huge_page() {
            return Err(MapError::Unsupported);
        }

        let p2 = self.p2_table(p4_index, p3_index);
        let p2_entry = unsafe { &mut (*p2).entries[p2_index] };
        if !p2_entry.is_present() {
            let frame = allocator
                .alloc(PageSize::Size4K)
                .ok_or(MapError::OutOfMemory)?;
            p2_entry.set_table(frame.start.as_usize());
            self.zero_table(self.p1_table(p4_index, p3_index, p2_index));
        } else if p2_entry.is_huge_page() {
            return Err(MapError::Unsupported);
        }

        let p1 = self.p1_table(p4_index, p3_index, p2_index);
        let entry = unsafe { &mut (*p1).entries[p1_index] };
        if entry.is_present() {
            return Err(MapError::AlreadyMapped);
        }
        entry.set_page(phys, perm);
        invlpg(virt);
        Ok(())
    }

    unsafe fn unmap_page(&self, virt: usize) -> Result<(), UnmapError> {
        let p4_index = (virt >> 39) & 0x1ff;
        let p3_index = (virt >> 30) & 0x1ff;
        let p2_index = (virt >> 21) & 0x1ff;
        let p1_index = (virt >> 12) & 0x1ff;

        let p4 = self.p4_table();
        let p4_entry = unsafe { &mut (*p4).entries[p4_index] };
        if !p4_entry.is_present() {
            return Err(UnmapError::NotMapped);
        }

        let p3 = self.p3_table(p4_index);
        let p3_entry = unsafe { &mut (*p3).entries[p3_index] };
        if !p3_entry.is_present() || p3_entry.is_huge_page() {
            return Err(UnmapError::NotMapped);
        }

        let p2 = self.p2_table(p4_index, p3_index);
        let p2_entry = unsafe { &mut (*p2).entries[p2_index] };
        if !p2_entry.is_present() || p2_entry.is_huge_page() {
            return Err(UnmapError::NotMapped);
        }

        let p1 = self.p1_table(p4_index, p3_index, p2_index);
        let entry = unsafe { &mut (*p1).entries[p1_index] };
        if !entry.is_present() {
            return Err(UnmapError::NotMapped);
        }

        entry.clear();
        invlpg(virt);
        Ok(())
    }

    unsafe fn translate(&self, virt: usize) -> Option<usize> {
        let p4_index = (virt >> 39) & 0x1ff;
        let p3_index = (virt >> 30) & 0x1ff;
        let p2_index = (virt >> 21) & 0x1ff;
        let p1_index = (virt >> 12) & 0x1ff;

        let p4 = self.p4_table();
        let p4_entry = unsafe { (*p4).entries[p4_index] };
        if !p4_entry.is_present() {
            return None;
        }

        let p3 = self.p3_table(p4_index);
        let p3_entry = unsafe { (*p3).entries[p3_index] };
        if !p3_entry.is_present() || p3_entry.is_huge_page() {
            return None;
        }

        let p2 = self.p2_table(p4_index, p3_index);
        let p2_entry = unsafe { (*p2).entries[p2_index] };
        if !p2_entry.is_present() || p2_entry.is_huge_page() {
            return None;
        }

        let p1 = self.p1_table(p4_index, p3_index, p2_index);
        let entry = unsafe { (*p1).entries[p1_index] };
        if !entry.is_present() {
            return None;
        }

        let frame = entry.frame_addr();
        let offset = virt & (PAGE_SIZE - 1);
        Some(frame + offset)
    }

    fn p4_table(&self) -> *mut PageTable {
        unsafe {
            self.table(
                self.recursive_index,
                self.recursive_index,
                self.recursive_index,
                self.recursive_index,
            )
        }
    }

    fn p3_table(&self, p4_index: usize) -> *mut PageTable {
        unsafe {
            self.table(
                self.recursive_index,
                self.recursive_index,
                self.recursive_index,
                p4_index,
            )
        }
    }

    fn p2_table(&self, p4_index: usize, p3_index: usize) -> *mut PageTable {
        unsafe {
            self.table(
                self.recursive_index,
                self.recursive_index,
                p4_index,
                p3_index,
            )
        }
    }

    fn p1_table(&self, p4_index: usize, p3_index: usize, p2_index: usize) -> *mut PageTable {
        unsafe { self.table(self.recursive_index, p4_index, p3_index, p2_index) }
    }

    unsafe fn table(&self, l4: usize, l3: usize, l2: usize, l1: usize) -> *mut PageTable {
        let addr = canonical_address(l4, l3, l2, l1);
        addr as *mut PageTable
    }

    fn zero_table(&self, table: *mut PageTable) {
        unsafe {
            ptr::write_bytes(table as *mut u8, 0, PAGE_SIZE);
        }
    }
}

#[repr(C)]
struct PageTable {
    entries: [PageTableEntry; ENTRIES_PER_TABLE],
}

#[repr(transparent)]
#[derive(Copy, Clone)]
struct PageTableEntry(u64);

impl PageTableEntry {
    fn is_present(&self) -> bool {
        self.0 & ENTRY_PRESENT != 0
    }

    fn is_huge_page(&self) -> bool {
        self.0 & ENTRY_HUGE_PAGE != 0
    }

    fn set_table(&mut self, frame: usize) {
        self.0 = (frame as u64) | ENTRY_PRESENT | ENTRY_WRITABLE;
    }

    fn set_page(&mut self, frame: usize, perm: MemPerm) {
        let mut value = (frame as u64) | ENTRY_PRESENT;
        if perm.is_writable() {
            value |= ENTRY_WRITABLE;
        }
        if perm.is_user_accessible() {
            value |= ENTRY_USER;
        }
        if !perm.is_executable() {
            value |= ENTRY_NO_EXECUTE;
        }
        self.0 = value;
    }

    fn frame_addr(&self) -> usize {
        (self.0 & ENTRY_ADDR_MASK) as usize
    }

    fn clear(&mut self) {
        self.0 = 0;
    }
}

fn canonical_address(p4: usize, p3: usize, p2: usize, p1: usize) -> usize {
    let raw = ((p4 as u64) << 39) | ((p3 as u64) << 30) | ((p2 as u64) << 21) | ((p1 as u64) << 12);
    if raw & (1 << 47) != 0 {
        (raw | 0xffff_0000_0000_0000) as usize
    } else {
        raw as usize
    }
}

fn invlpg(addr: usize) {
    unsafe {
        asm!("invlpg [{0}]", in(reg) addr as *const u8, options(nostack, preserves_flags));
    }
}

fn align_down(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    value & !(align - 1)
}
