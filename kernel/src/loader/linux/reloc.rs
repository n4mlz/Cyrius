use crate::mem::addr::{Addr, MemPerm, Page, PageSize, VirtAddr, align_down, align_up};
use crate::mem::paging::PageTableOps;
use crate::mem::user::{UserAccessError, UserMemoryAccess};
use crate::println;

use super::LinuxLoadError;
use super::add_base;
use super::elf::{DynamicSegment, RelroSegment};
use super::map::MappedSegment;

const DT_NULL: i64 = 0;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;

const R_X86_64_RELATIVE: u32 = 8;

#[derive(Debug, Default)]
pub struct DynamicInfo {
    pub rela_addr: Option<VirtAddr>,
    pub rela_size: usize,
    pub rela_ent: usize,
}

pub fn read_dynamic_info<T: PageTableOps>(
    table: &T,
    base: VirtAddr,
    segment: &DynamicSegment,
) -> Result<DynamicInfo, LinuxLoadError> {
    let dyn_addr = add_base(base, segment.vaddr)?;
    let user = UserMemoryAccess::new(table);
    let mut info = DynamicInfo::default();
    let mut offset = 0usize;
    let entry_size = core::mem::size_of::<Elf64Dyn>();
    if segment.mem_size % entry_size != 0 {
        return Err(LinuxLoadError::InvalidElf(
            "dynamic section size misaligned",
        ));
    }

    while offset < segment.mem_size {
        let entry_addr = dyn_addr
            .checked_add(offset)
            .ok_or(LinuxLoadError::SizeOverflow)?;
        let tag = user.read_u64(entry_addr)? as i64;
        let val = user.read_u64(
            entry_addr
                .checked_add(8)
                .ok_or(LinuxLoadError::SizeOverflow)?,
        )?;
        if tag == DT_NULL {
            break;
        }
        match tag {
            DT_RELA => {
                info.rela_addr = Some(VirtAddr::new(
                    usize::try_from(val).map_err(|_| LinuxLoadError::SizeOverflow)?,
                ));
            }
            DT_RELASZ => {
                info.rela_size = usize::try_from(val).map_err(|_| LinuxLoadError::SizeOverflow)?;
            }
            DT_RELAENT => {
                info.rela_ent = usize::try_from(val).map_err(|_| LinuxLoadError::SizeOverflow)?;
            }
            _ => {}
        }
        offset = offset
            .checked_add(entry_size)
            .ok_or(LinuxLoadError::SizeOverflow)?;
    }

    if info.rela_size > 0 && info.rela_ent == 0 {
        return Err(LinuxLoadError::InvalidElf("DT_RELAENT missing"));
    }
    if info.rela_size > 0 && info.rela_addr.is_none() {
        return Err(LinuxLoadError::InvalidElf("DT_RELA missing"));
    }
    Ok(info)
}

pub fn apply_relocations<T: PageTableOps>(
    table: &T,
    base: VirtAddr,
    info: &DynamicInfo,
    segments: &[MappedSegment],
) -> Result<(), LinuxLoadError> {
    let rela_addr = match info.rela_addr {
        Some(addr) => add_base(base, addr)?,
        None => return Ok(()),
    };
    if info.rela_size == 0 {
        return Ok(());
    }
    let entry_size = core::mem::size_of::<Elf64Rela>();
    if info.rela_ent != entry_size {
        return Err(LinuxLoadError::InvalidElf("unexpected Rela entry size"));
    }
    if info.rela_size % entry_size != 0 {
        return Err(LinuxLoadError::InvalidElf("Rela size not aligned"));
    }

    let user = UserMemoryAccess::new(table);
    let count = info.rela_size / entry_size;
    for idx in 0..count {
        let entry_addr = rela_addr
            .checked_add(idx * entry_size)
            .ok_or(LinuxLoadError::SizeOverflow)?;
        let r_offset = user.read_u64(entry_addr)?;
        let r_info = user.read_u64(
            entry_addr
                .checked_add(8)
                .ok_or(LinuxLoadError::SizeOverflow)?,
        )?;
        let r_addend = user.read_u64(
            entry_addr
                .checked_add(16)
                .ok_or(LinuxLoadError::SizeOverflow)?,
        )? as i64;

        let reloc_type = (r_info & 0xffff_ffff) as u32;
        if reloc_type != R_X86_64_RELATIVE {
            return Err(LinuxLoadError::UnsupportedRelocation(reloc_type));
        }

        let target = base
            .checked_add(usize::try_from(r_offset).map_err(|_| LinuxLoadError::SizeOverflow)?)
            .ok_or(LinuxLoadError::SizeOverflow)?;
        if !is_mapped(target, segments) {
            return Err(LinuxLoadError::RelocationTargetOutOfRange);
        }

        let base_raw = base.as_raw() as i64;
        let value_raw = base_raw
            .checked_add(r_addend)
            .ok_or(LinuxLoadError::SizeOverflow)?;
        if value_raw < 0 {
            return Err(LinuxLoadError::RelocationTargetOutOfRange);
        }
        user.write_u64(target, value_raw as u64)?;
    }

    Ok(())
}

pub fn apply_gnu_relro<T: PageTableOps>(
    table: &mut T,
    base: VirtAddr,
    relro: &RelroSegment,
    segments: &[MappedSegment],
) -> Result<(), LinuxLoadError> {
    if relro.mem_size == 0 {
        return Ok(());
    }

    let relro_start = add_base(base, relro.vaddr)?;
    let relro_end = relro_start
        .checked_add(relro.mem_size)
        .ok_or(LinuxLoadError::SizeOverflow)?;
    let page_size = PageSize::SIZE_4K.bytes();
    let start = align_down(relro_start.as_raw(), page_size);
    let end = align_up(relro_end.as_raw(), page_size);

    println!(
        "[loader] GNU_RELRO {:#x}-{:#x}",
        relro_start.as_raw(),
        relro_end.as_raw()
    );

    for addr in (start..end).step_by(page_size) {
        let page_start = addr;
        let page_end = addr
            .checked_add(page_size)
            .ok_or(LinuxLoadError::SizeOverflow)?;
        if relro_start.as_raw() > page_start || relro_end.as_raw() < page_end {
            println!(
                "[loader] relro page {:#x}-{:#x} skipped (partial coverage)",
                page_start, page_end
            );
            continue;
        }
        let page = Page::new(VirtAddr::new(addr), PageSize(page_size));
        let perms = segment_perms_for(VirtAddr::new(addr), segments)
            .ok_or(LinuxLoadError::RelocationTargetOutOfRange)?;
        let new_perms = perms & !MemPerm::WRITE;
        table.update_permissions(page, new_perms)?;
    }

    Ok(())
}

fn is_mapped(addr: VirtAddr, segments: &[MappedSegment]) -> bool {
    segments
        .iter()
        .any(|seg| addr >= seg.start && addr < seg.end)
}

fn segment_perms_for(addr: VirtAddr, segments: &[MappedSegment]) -> Option<MemPerm> {
    segments
        .iter()
        .find(|seg| addr >= seg.start && addr < seg.end)
        .map(|seg| seg.perms)
}

impl From<UserAccessError> for LinuxLoadError {
    fn from(err: UserAccessError) -> Self {
        LinuxLoadError::UserAccess(err)
    }
}

#[repr(C)]
struct Elf64Dyn {
    _tag: i64,
    _val: u64,
}

#[repr(C)]
struct Elf64Rela {
    _offset: u64,
    _info: u64,
    _addend: i64,
}
