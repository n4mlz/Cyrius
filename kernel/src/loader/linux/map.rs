use crate::arch::api::{ArchLinuxElfPlatform, ArchPageTableAccess};
use crate::mem::addr::{MemPerm, Page, PageSize, VirtAddr, VirtIntoPtr, align_down, align_up};
use crate::mem::manager;
use crate::mem::paging::{FrameAllocator, PageTableOps};
use crate::mem::paging::{MapError, PhysMapper, TranslationError};

use super::LinuxLoadError;
use super::elf::{ElfFile, ProgramSegment};
use super::patch::rewrite_syscalls_in_table;
use super::add_base;
use alloc::vec::Vec;

pub struct MappedSegment {
    pub start: VirtAddr,
    pub end: VirtAddr,
    pub perms: MemPerm,
    pub page_size: usize,
}

pub fn map_segments<P: ArchLinuxElfPlatform>(
    space: &P::AddressSpace,
    elf: &ElfFile,
    image: &[u8],
    base: VirtAddr,
) -> Result<Vec<MappedSegment>, LinuxLoadError> {
    space.with_page_table(|table, allocator| {
        let mut mapped = alloc::vec::Vec::new();
        for seg in &elf.segments {
            if let Some(segment) = map_single_segment::<_, _, P>(table, allocator, seg, image, base)?
            {
                mapped.push(segment);
            }
        }
        Ok(mapped)
    })
}

pub fn apply_segment_permissions<T: PageTableOps>(
    table: &mut T,
    segments: &[MappedSegment],
) -> Result<(), LinuxLoadError> {
    for seg in segments {
        for addr in (seg.start.as_raw()..seg.end.as_raw()).step_by(seg.page_size) {
            let page = Page::new(VirtAddr::new(addr), PageSize(seg.page_size));
            table.update_permissions(page, seg.perms)?;
        }
    }
    Ok(())
}

fn map_single_segment<T: PageTableOps, A: FrameAllocator, P: ArchLinuxElfPlatform>(
    table: &mut T,
    allocator: &mut A,
    seg: &ProgramSegment,
    image: &[u8],
    base: VirtAddr,
) -> Result<Option<MappedSegment>, LinuxLoadError> {
    if seg.mem_size == 0 {
        return Ok(None);
    }

    // Map with write permissions for population; tighten later if necessary.
    let target_perms = perms_from_flags(seg.flags);
    let map_perms = target_perms | MemPerm::WRITE;

    let page_size = P::page_size();
    let seg_vaddr = add_base(base, seg.vaddr)?;
    let start = align_down(seg_vaddr.as_raw(), page_size);
    let end = align_up(
        seg_vaddr
            .as_raw()
            .checked_add(seg.mem_size)
            .ok_or(LinuxLoadError::SizeOverflow)?,
        page_size,
    );

    let page_sz = PageSize(page_size);
    clear_segment_range(table, allocator, start, end, page_sz);
    for addr in (start..end).step_by(page_size) {
        let virt = VirtAddr::new(addr);
        let page = Page::new(virt, page_sz);
        let frame = allocator
            .allocate(page_sz)
            .ok_or(LinuxLoadError::FrameAllocationFailed)?;
        table.map(page, frame, map_perms, allocator)?;
    }

    // Copy file-backed bytes.
    let file_range = seg
        .offset
        .checked_add(seg.file_size)
        .ok_or(LinuxLoadError::SizeOverflow)?;
    let file_slice = image
        .get(seg.offset..file_range)
        .ok_or(LinuxLoadError::InvalidElf("segment out of file bounds"))?;
    copy_into_mapped(table, seg_vaddr, file_slice)?;

    // Zero BSS.
    if seg.mem_size > seg.file_size {
        let bss_start = seg_vaddr
            .as_raw()
            .checked_add(seg.file_size)
            .ok_or(LinuxLoadError::SizeOverflow)?;
        let bss_len = seg.mem_size - seg.file_size;
        zero_mapped(table, VirtAddr::new(bss_start), bss_len)?;
    }

    if target_perms.contains(MemPerm::EXEC) && seg.file_size > 0 {
        rewrite_syscalls_in_table(seg_vaddr, seg.file_size, table)
            .map_err(LinuxLoadError::from)?;
    }

    Ok(Some(MappedSegment {
        start: VirtAddr::new(start),
        end: VirtAddr::new(end),
        perms: target_perms,
        page_size,
    }))
}

fn copy_into_mapped<T: PageTableOps>(
    table: &T,
    dst: VirtAddr,
    src: &[u8],
) -> Result<(), LinuxLoadError> {
    let mapper = manager::phys_mapper();
    let mut offset = 0usize;
    while offset < src.len() {
        let addr = dst
            .as_raw()
            .checked_add(offset)
            .ok_or(LinuxLoadError::SizeOverflow)?;
        let virt = VirtAddr::new(addr);
        let phys = table.translate(virt).map_err(LinuxLoadError::from)?;
        let page_offset = addr % PageSize::SIZE_4K.bytes();
        let len = (PageSize::SIZE_4K.bytes() - page_offset).min(src.len() - offset);
        unsafe {
            let ptr = mapper.phys_to_virt(phys);
            core::ptr::copy_nonoverlapping(src[offset..].as_ptr(), ptr.into_mut_ptr(), len);
        }
        offset += len;
    }
    Ok(())
}

fn zero_mapped<T: PageTableOps>(
    table: &T,
    dst: VirtAddr,
    len: usize,
) -> Result<(), LinuxLoadError> {
    let mapper = manager::phys_mapper();
    let mut offset = 0usize;
    while offset < len {
        let addr = dst
            .as_raw()
            .checked_add(offset)
            .ok_or(LinuxLoadError::SizeOverflow)?;
        let virt = VirtAddr::new(addr);
        let phys = table.translate(virt).map_err(LinuxLoadError::from)?;
        let page_offset = addr % PageSize::SIZE_4K.bytes();
        let chunk = (PageSize::SIZE_4K.bytes() - page_offset).min(len - offset);
        unsafe {
            let ptr = mapper.phys_to_virt(phys);
            core::ptr::write_bytes(ptr.into_mut_ptr(), 0, chunk);
        }
        offset += chunk;
    }
    Ok(())
}

impl From<TranslationError> for LinuxLoadError {
    fn from(err: TranslationError) -> Self {
        let map_err = match err {
            TranslationError::NotMapped => MapError::NotMapped,
            TranslationError::HugePage => MapError::UnsupportedPageSize(PageSize::SIZE_4K),
        };
        LinuxLoadError::Map(map_err)
    }
}

fn perms_from_flags(flags: u32) -> MemPerm {
    let mut perms = MemPerm::USER_R;
    if flags & 0x2 != 0 {
        perms |= MemPerm::WRITE;
    }
    if flags & 0x1 != 0 {
        perms |= MemPerm::EXEC;
    }
    perms
}

fn clear_segment_range<T: PageTableOps, A: FrameAllocator>(
    table: &mut T,
    allocator: &mut A,
    start: usize,
    end: usize,
    page_sz: PageSize,
) {
    for addr in (start..end).step_by(page_sz.bytes()) {
        let page = Page::new(VirtAddr::new(addr), page_sz);
        if let Ok(frame) = table.unmap(page) {
            allocator.deallocate(frame);
        }
    }
}
