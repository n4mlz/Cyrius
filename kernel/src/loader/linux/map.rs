use crate::arch::api::{ArchLinuxElfPlatform, ArchPageTableAccess};
use crate::mem::addr::{MemPerm, Page, PageSize, VirtAddr, VirtIntoPtr, align_down, align_up};
use crate::mem::paging::{FrameAllocator, PageTableOps};

use super::elf::{ElfFile, ProgramSegment};
use super::patch::rewrite_syscalls;
use super::LinuxLoadError;

pub fn map_segments<P: ArchLinuxElfPlatform>(
    space: &P::AddressSpace,
    elf: &ElfFile,
    image: &[u8],
) -> Result<(), LinuxLoadError> {
    space.with_page_table(|table, allocator| {
        for seg in &elf.segments {
            map_single_segment::<_, _, P>(table, allocator, seg, image)?;
        }
        Ok(())
    })
}

fn map_single_segment<T: PageTableOps, A: FrameAllocator, P: ArchLinuxElfPlatform>(
    table: &mut T,
    allocator: &mut A,
    seg: &ProgramSegment,
    image: &[u8],
) -> Result<(), LinuxLoadError> {
    if seg.mem_size == 0 {
        return Ok(());
    }

    // Map with write permissions for population; tighten later if necessary.
    let target_perms = perms_from_flags(seg.flags);
    let map_perms = target_perms | MemPerm::WRITE;

    let page_size = P::page_size();
    let start = align_down(seg.vaddr.as_raw(), page_size);
    let end = align_up(
        seg.vaddr
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
    let dst = seg
        .vaddr
        .as_raw()
        .checked_add(seg.file_size)
        .ok_or(LinuxLoadError::SizeOverflow)?;

    unsafe {
        core::ptr::copy_nonoverlapping(
            file_slice.as_ptr(),
            seg.vaddr.into_mut_ptr(),
            seg.file_size,
        );
        // Zero BSS.
        if seg.mem_size > seg.file_size {
            core::ptr::write_bytes(
                VirtAddr::new(dst).into_mut_ptr(),
                0,
                seg.mem_size - seg.file_size,
            );
        }
    }

    if target_perms.contains(MemPerm::EXEC) && seg.file_size > 0 {
        rewrite_syscalls(seg);
    }

    if !target_perms.contains(MemPerm::WRITE) {
        for addr in (start..end).step_by(page_size) {
            let page = Page::new(VirtAddr::new(addr), page_sz);
            table.update_permissions(page, target_perms)?;
        }
    }

    Ok(())
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
