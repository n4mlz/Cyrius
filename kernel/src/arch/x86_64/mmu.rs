use core::arch::asm;
use core::ptr;

use crate::arch::api::ArchMmu;
use crate::boot::BootInfo;
use crate::mem::addr::{Addr, AddrRange, PageSize, PhysAddr, VirtAddr};
use crate::mem::frame::{BootFrameAllocator, FrameAllocator};
use crate::mem::paging::MapError;
use crate::util::align_up;
use crate::util::spinlock::SpinLock;

use super::X86BootInfo;

const PAGE_SIZE: usize = 0x1000;
const ENTRIES_PER_TABLE: usize = 512;
const HEAP_VIRT_START: usize = 0xffff_8000_0000_0000;

const ENTRY_PRESENT: u64 = 1;
const ENTRY_WRITABLE: u64 = 1 << 1;
const ENTRY_NO_EXECUTE: u64 = 1 << 63;

#[derive(Copy, Clone, Debug)]
struct HeapMapping {
    phys: AddrRange<PhysAddr>,
    virt: AddrRange<VirtAddr>,
}

pub struct X86Mmu {
    recursive_index: SpinLock<Option<usize>>,
    heap_mapping: SpinLock<Option<HeapMapping>>,
}

static MMU: X86Mmu = X86Mmu::new();

impl X86Mmu {
    pub const fn new() -> Self {
        Self {
            recursive_index: SpinLock::new(None),
            heap_mapping: SpinLock::new(None),
        }
    }

    pub fn instance() -> &'static Self {
        &MMU
    }

    fn recursive_index(&self) -> Result<usize, MapError> {
        let guard = self.recursive_index.lock();
        guard.ok_or(MapError::Unsupported)
    }

    fn record_heap_mapping(&self, mapping: HeapMapping) {
        let mut guard = self.heap_mapping.lock();
        *guard = Some(mapping);
    }

    fn current_heap_mapping(&self) -> Option<HeapMapping> {
        *self.heap_mapping.lock()
    }
}

impl ArchMmu<X86BootInfo> for X86Mmu {
    fn init(&self, boot_info: &BootInfo<X86BootInfo>) {
        let mut guard = self.recursive_index.lock();
        if guard.is_none() {
            *guard = boot_info.arch_data.recursive_index.map(|idx| idx as usize);
        }
    }

    fn map_heap(
        &self,
        boot_info: &BootInfo<X86BootInfo>,
        phys_range: AddrRange<PhysAddr>,
    ) -> Result<AddrRange<VirtAddr>, MapError> {
        let recursive_index = self.recursive_index()?;

        let start =
            align_up(phys_range.start.as_usize(), PAGE_SIZE).ok_or(MapError::InvalidAddress)?;
        let end = phys_range.end.as_usize() & !(PAGE_SIZE - 1);

        if start >= end {
            return Err(MapError::InvalidAddress);
        }

        let aligned_phys = AddrRange {
            start: PhysAddr::from_usize(start),
            end: PhysAddr::from_usize(end),
        };

        let length = end - start;
        let virt_start = HEAP_VIRT_START;
        let virt_end = virt_start
            .checked_add(length)
            .ok_or(MapError::InvalidAddress)?;
        let virt_range = AddrRange {
            start: VirtAddr::from_usize(virt_start),
            end: VirtAddr::from_usize(virt_end),
        };

        let mut frame_allocator =
            BootFrameAllocator::with_reservation_from_boot_info(boot_info, aligned_phys);
        let mapper = RecursiveMapper::new(recursive_index);

        let mut offset = 0usize;
        while offset < length {
            let virt = virt_start + offset;
            let phys = start + offset;
            unsafe {
                mapper.map_page(virt, phys, &mut frame_allocator)?;
            }
            offset += PAGE_SIZE;
        }

        self.record_heap_mapping(HeapMapping {
            phys: aligned_phys,
            virt: virt_range,
        });

        Ok(virt_range)
    }

    fn phys_to_virt(&self, phys: PhysAddr) -> Option<VirtAddr> {
        let mapping = self.current_heap_mapping()?;
        let phys_addr = phys.as_usize();
        let start = mapping.phys.start.as_usize();
        let end = mapping.phys.end.as_usize();
        if phys_addr < start || phys_addr >= end {
            return None;
        }
        let offset = phys_addr - start;
        Some(VirtAddr::from_usize(mapping.virt.start.as_usize() + offset))
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
            p4_entry.set_frame(frame.start.as_usize());
            self.zero_table(self.p3_table(p4_index));
        }

        let p3 = self.p3_table(p4_index);
        let p3_entry = unsafe { &mut (*p3).entries[p3_index] };
        if !p3_entry.is_present() {
            let frame = allocator
                .alloc(PageSize::Size4K)
                .ok_or(MapError::OutOfMemory)?;
            p3_entry.set_frame(frame.start.as_usize());
            self.zero_table(self.p2_table(p4_index, p3_index));
        }

        let p2 = self.p2_table(p4_index, p3_index);
        let p2_entry = unsafe { &mut (*p2).entries[p2_index] };
        if !p2_entry.is_present() {
            let frame = allocator
                .alloc(PageSize::Size4K)
                .ok_or(MapError::OutOfMemory)?;
            p2_entry.set_frame(frame.start.as_usize());
            self.zero_table(self.p1_table(p4_index, p3_index, p2_index));
        }

        let p1 = self.p1_table(p4_index, p3_index, p2_index);
        let entry = unsafe { &mut (*p1).entries[p1_index] };
        if entry.is_present() {
            return Err(MapError::AlreadyMapped);
        }
        entry.set_page(phys);
        invlpg(virt);
        Ok(())
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
struct PageTableEntry(u64);

impl PageTableEntry {
    fn is_present(&self) -> bool {
        self.0 & ENTRY_PRESENT != 0
    }

    fn set_frame(&mut self, frame: usize) {
        self.0 = (frame as u64) | ENTRY_PRESENT | ENTRY_WRITABLE;
    }

    fn set_page(&mut self, frame: usize) {
        self.0 = (frame as u64) | ENTRY_PRESENT | ENTRY_WRITABLE | ENTRY_NO_EXECUTE;
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
