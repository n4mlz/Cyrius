use crate::mem::addr::{Addr, MemPerm, Page, PageSize, VirtAddr, align_down, align_up};
use crate::mem::paging::PageTableOps;
use crate::mem::user::{UserAccessError, UserMemoryAccess};

use super::LinuxLoadError;
use super::add_base;
use super::elf::{DynamicSegment, RelroSegment};
use super::map::MappedSegment;

const DT_NULL: i64 = 0;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_REL: i64 = 17;
const DT_RELSZ: i64 = 18;
const DT_RELENT: i64 = 19;
const DT_PLTREL: i64 = 20;
const DT_JMPREL: i64 = 23;
const DT_PLTRELSZ: i64 = 2;
const DT_RELRSZ: i64 = 35;
const DT_RELR: i64 = 36;
const DT_RELRENT: i64 = 37;

const R_X86_64_RELATIVE: u32 = 8;


#[derive(Debug, Default)]
pub struct DynamicInfo {
    pub rela_addr: Option<VirtAddr>,
    pub rela_size: usize,
    pub rela_ent: usize,
    pub rel_addr: Option<VirtAddr>,
    pub rel_size: usize,
    pub rel_ent: usize,
    pub jmprel_addr: Option<VirtAddr>,
    pub jmprel_size: usize,
    pub jmprel_is_rela: bool,
    pub relr_addr: Option<VirtAddr>,
    pub relr_size: usize,
    pub relr_ent: usize,
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
    info.jmprel_is_rela = true;
    if !segment.mem_size.is_multiple_of(entry_size) {
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
                let raw = usize::try_from(val).map_err(|_| LinuxLoadError::SizeOverflow)?;
                info.rela_addr = Some(resolve_dynamic_ptr(table, base, raw)?);
            }
            DT_RELASZ => {
                info.rela_size = usize::try_from(val).map_err(|_| LinuxLoadError::SizeOverflow)?;
            }
            DT_RELAENT => {
                info.rela_ent = usize::try_from(val).map_err(|_| LinuxLoadError::SizeOverflow)?;
            }
            DT_REL => {
                let raw = usize::try_from(val).map_err(|_| LinuxLoadError::SizeOverflow)?;
                info.rel_addr = Some(resolve_dynamic_ptr(table, base, raw)?);
            }
            DT_RELSZ => {
                info.rel_size = usize::try_from(val).map_err(|_| LinuxLoadError::SizeOverflow)?;
            }
            DT_RELENT => {
                info.rel_ent = usize::try_from(val).map_err(|_| LinuxLoadError::SizeOverflow)?;
            }
            DT_JMPREL => {
                let raw = usize::try_from(val).map_err(|_| LinuxLoadError::SizeOverflow)?;
                info.jmprel_addr = Some(resolve_dynamic_ptr(table, base, raw)?);
            }
            DT_PLTRELSZ => {
                info.jmprel_size =
                    usize::try_from(val).map_err(|_| LinuxLoadError::SizeOverflow)?;
            }
            DT_PLTREL => {
                info.jmprel_is_rela = match val as i64 {
                    DT_RELA => true,
                    DT_REL => false,
                    _ => return Err(LinuxLoadError::InvalidElf("unsupported PLTREL type")),
                };
            }
            DT_RELR => {
                let raw = usize::try_from(val).map_err(|_| LinuxLoadError::SizeOverflow)?;
                info.relr_addr = Some(resolve_dynamic_ptr(table, base, raw)?);
            }
            DT_RELRSZ => {
                info.relr_size = usize::try_from(val).map_err(|_| LinuxLoadError::SizeOverflow)?;
            }
            DT_RELRENT => {
                info.relr_ent = usize::try_from(val).map_err(|_| LinuxLoadError::SizeOverflow)?;
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
    if info.rel_size > 0 && info.rel_ent == 0 {
        return Err(LinuxLoadError::InvalidElf("DT_RELENT missing"));
    }
    if info.rel_size > 0 && info.rel_addr.is_none() {
        return Err(LinuxLoadError::InvalidElf("DT_REL missing"));
    }
    if info.jmprel_size > 0 && info.jmprel_addr.is_none() {
        return Err(LinuxLoadError::InvalidElf("DT_JMPREL missing"));
    }
    if info.relr_size > 0 && info.relr_addr.is_none() {
        return Err(LinuxLoadError::InvalidElf("DT_RELR missing"));
    }
    if let (Some(rela_addr), true) = (info.rela_addr, info.rela_size > 0) {
        crate::println!(
            "[loader] rela addr={:#x} size={:#x} ent={:#x}",
            rela_addr.as_raw(),
            info.rela_size,
            info.rela_ent
        );
        let entry_size = core::mem::size_of::<Elf64Rela>();
        if entry_size > 0 && info.rela_size.is_multiple_of(entry_size) {
            let count = (info.rela_size / entry_size).min(3);
            for idx in 0..count {
                let entry_addr = match rela_addr.checked_add(idx * entry_size) {
                    Some(addr) => addr,
                    None => break,
                };
                let r_offset = match user.read_u64(entry_addr) {
                    Ok(val) => val,
                    Err(_) => break,
                };
                let r_info = match user.read_u64(entry_addr.checked_add(8).unwrap_or(entry_addr)) {
                    Ok(val) => val,
                    Err(_) => break,
                };
                let r_addend =
                    match user.read_u64(entry_addr.checked_add(16).unwrap_or(entry_addr)) {
                        Ok(val) => val as i64,
                        Err(_) => break,
                    };
                crate::println!(
                    "[loader] rela[{}] r_offset={:#x} r_info={:#x} r_addend={:#x}",
                    idx,
                    r_offset,
                    r_info,
                    r_addend
                );
            }
        }
    }
    Ok(info)
}

pub fn apply_relocations<T: PageTableOps>(
    table: &T,
    base: VirtAddr,
    info: &DynamicInfo,
    segments: &[MappedSegment],
) -> Result<(), LinuxLoadError> {
    crate::println!(
        "[loader] apply relocations base={:#x}",
        base.as_raw()
    );
    apply_rel(table, base, info, segments)?;
    apply_rela(table, base, info, segments)?;
    apply_relr(table, base, info, segments)?;
    apply_jmprel(table, base, info, segments)?;
    Ok(())
}

fn apply_rel<T: PageTableOps>(
    table: &T,
    base: VirtAddr,
    info: &DynamicInfo,
    segments: &[MappedSegment],
) -> Result<(), LinuxLoadError> {
    let rel_addr = match info.rel_addr {
        Some(addr) => addr,
        None => return Ok(()),
    };
    apply_rel_table(table, base, rel_addr, info.rel_size, info.rel_ent, segments, "REL")
}

fn apply_rela<T: PageTableOps>(
    table: &T,
    base: VirtAddr,
    info: &DynamicInfo,
    segments: &[MappedSegment],
) -> Result<(), LinuxLoadError> {
    let rela_addr = match info.rela_addr {
        Some(addr) => addr,
        None => return Ok(()),
    };
    apply_rela_table(table, base, rela_addr, info.rela_size, info.rela_ent, segments, "RELA")
}

fn apply_jmprel<T: PageTableOps>(
    table: &T,
    base: VirtAddr,
    info: &DynamicInfo,
    segments: &[MappedSegment],
) -> Result<(), LinuxLoadError> {
    let jmprel_addr = match info.jmprel_addr {
        Some(addr) => addr,
        None => return Ok(()),
    };
    if info.jmprel_size == 0 {
        return Ok(());
    }
    if info.jmprel_is_rela {
        apply_rela_table(
            table,
            base,
            jmprel_addr,
            info.jmprel_size,
            core::mem::size_of::<Elf64Rela>(),
            segments,
            "JMPRELA",
        )
    } else {
        apply_rel_table(
            table,
            base,
            jmprel_addr,
            info.jmprel_size,
            core::mem::size_of::<Elf64Rel>(),
            segments,
            "JMPREL",
        )
    }
}

fn apply_rela_table<T: PageTableOps>(
    table: &T,
    base: VirtAddr,
    rela_addr: VirtAddr,
    rela_size: usize,
    rela_ent: usize,
    segments: &[MappedSegment],
    _label: &str,
) -> Result<(), LinuxLoadError> {
    if rela_size == 0 {
        return Ok(());
    }
    let entry_size = core::mem::size_of::<Elf64Rela>();
    if rela_ent != entry_size {
        return Err(LinuxLoadError::InvalidElf("unexpected Rela entry size"));
    }
    if !rela_size.is_multiple_of(entry_size) {
        return Err(LinuxLoadError::InvalidElf("Rela size not aligned"));
    }

    let user = UserMemoryAccess::new(table);
    let count = rela_size / entry_size;
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
        let sym = (r_info >> 32) as u32;
        let reloc_type = (r_info & 0xffff_ffff) as u32;
        let raw_offset = usize::try_from(r_offset).map_err(|_| LinuxLoadError::SizeOverflow)?;
        let target = resolve_reloc_target(base, raw_offset, segments)?;
        let value_raw = resolve_symbol_reloc(base, reloc_type, sym, r_addend, segments)?;
        let value_addr = VirtAddr::new(value_raw as usize);
        if !is_mapped(value_addr, segments) {
            crate::println!(
                "[loader] rela[{}] unmapped value r_offset={:#x} target={:#x} addend={:#x} value={:#x}",
                idx,
                r_offset,
                target.as_raw(),
                r_addend,
                value_raw
            );
        }
        user.write_u64(target, value_raw)?;
    }

    Ok(())
}

fn apply_rel_table<T: PageTableOps>(
    table: &T,
    base: VirtAddr,
    rel_addr: VirtAddr,
    rel_size: usize,
    rel_ent: usize,
    segments: &[MappedSegment],
    _label: &str,
) -> Result<(), LinuxLoadError> {
    if rel_size == 0 {
        return Ok(());
    }
    let entry_size = core::mem::size_of::<Elf64Rel>();
    if rel_ent != entry_size {
        return Err(LinuxLoadError::InvalidElf("unexpected Rel entry size"));
    }
    if !rel_size.is_multiple_of(entry_size) {
        return Err(LinuxLoadError::InvalidElf("Rel size not aligned"));
    }

    let user = UserMemoryAccess::new(table);
    let count = rel_size / entry_size;
    for idx in 0..count {
        let entry_addr = rel_addr
            .checked_add(idx * entry_size)
            .ok_or(LinuxLoadError::SizeOverflow)?;
        let r_offset = user.read_u64(entry_addr)?;
        let r_info = user.read_u64(
            entry_addr
                .checked_add(8)
                .ok_or(LinuxLoadError::SizeOverflow)?,
        )?;
        let sym = (r_info >> 32) as u32;
        let reloc_type = (r_info & 0xffff_ffff) as u32;

        let raw_offset = usize::try_from(r_offset).map_err(|_| LinuxLoadError::SizeOverflow)?;
        let target = resolve_reloc_target(base, raw_offset, segments)?;
        let addend = user_read_u64(table, target)? as i64;
        let value = resolve_symbol_reloc(base, reloc_type, sym, addend, segments)?;
        user.write_u64(target, value)?;
    }
    Ok(())
}

fn apply_relr<T: PageTableOps>(
    table: &T,
    base: VirtAddr,
    info: &DynamicInfo,
    segments: &[MappedSegment],
) -> Result<(), LinuxLoadError> {
    let relr_addr = match info.relr_addr {
        Some(addr) => addr,
        None => return Ok(()),
    };
    if info.relr_size == 0 {
        return Ok(());
    }
    let entry_size = core::mem::size_of::<u64>();
    if info.relr_ent != 0 && info.relr_ent != entry_size {
        return Err(LinuxLoadError::InvalidElf("unexpected RELR entry size"));
    }
    if !info.relr_size.is_multiple_of(entry_size) {
        return Err(LinuxLoadError::InvalidElf("RELR size not aligned"));
    }

    let user = UserMemoryAccess::new(table);
    let count = info.relr_size / entry_size;
    let mut base_offset = 0usize;
    for idx in 0..count {
        let entry_addr = relr_addr
            .checked_add(idx * entry_size)
            .ok_or(LinuxLoadError::SizeOverflow)?;
        let entry = user.read_u64(entry_addr)?;
        if entry & 1 == 0 {
            base_offset = usize::try_from(entry).map_err(|_| LinuxLoadError::SizeOverflow)?;
            apply_relative_at(table, base, base_offset, segments)?;
            base_offset = base_offset
                .checked_add(entry_size)
                .ok_or(LinuxLoadError::SizeOverflow)?;
        } else {
            let mut bitmap = entry >> 1;
            for bit in 0..(u64::BITS - 1) {
                if (bitmap & 1) != 0 {
                    let rel = base_offset
                        .checked_add(bit as usize * entry_size)
                        .ok_or(LinuxLoadError::SizeOverflow)?;
                    apply_relative_at(table, base, rel, segments)?;
                }
                bitmap >>= 1;
            }
            base_offset = base_offset
                .checked_add((u64::BITS as usize - 1) * entry_size)
                .ok_or(LinuxLoadError::SizeOverflow)?;
        }
    }
    Ok(())
}

fn apply_relative_at<T: PageTableOps>(
    table: &T,
    base: VirtAddr,
    rel: usize,
    segments: &[MappedSegment],
) -> Result<(), LinuxLoadError> {
    let target = resolve_reloc_target(base, rel, segments)?;
    let addend = user_read_u64(table, target)? as i64;
    let value_raw = resolve_relative_value(base, addend, segments)?;
    let user = UserMemoryAccess::new(table);
    user.write_u64(target, value_raw)?;
    Ok(())
}

fn user_read_u64<T: PageTableOps>(
    table: &T,
    addr: VirtAddr,
) -> Result<u64, LinuxLoadError> {
    let user = UserMemoryAccess::new(table);
    user.read_u64(addr).map_err(LinuxLoadError::from)
}

fn resolve_reloc_target(
    base: VirtAddr,
    raw: usize,
    segments: &[MappedSegment],
) -> Result<VirtAddr, LinuxLoadError> {
    let base_target = base
        .checked_add(raw)
        .ok_or(LinuxLoadError::SizeOverflow)?;
    if is_mapped(base_target, segments) {
        return Ok(base_target);
    }
    Err(LinuxLoadError::RelocationTargetOutOfRange)
}

/// Resolve dynamic pointers that may be encoded as base-relative or absolute.
fn resolve_dynamic_ptr<T: PageTableOps>(
    table: &T,
    base: VirtAddr,
    raw: usize,
) -> Result<VirtAddr, LinuxLoadError> {
    let base_addr = add_base(base, VirtAddr::new(raw))?;
    if table.translate(base_addr).is_ok() {
        return Ok(base_addr);
    }
    let abs_addr = VirtAddr::new(raw);
    if table.translate(abs_addr).is_ok() {
        return Ok(abs_addr);
    }
    Err(LinuxLoadError::InvalidElf("dynamic pointer out of range"))
}

fn resolve_relative_value(
    base: VirtAddr,
    addend: i64,
    segments: &[MappedSegment],
) -> Result<u64, LinuxLoadError> {
    if addend < 0 {
        return Err(LinuxLoadError::RelocationTargetOutOfRange);
    }
    let addend_usize = addend as usize;
    let base_value = base
        .as_raw()
        .checked_add(addend_usize)
        .ok_or(LinuxLoadError::SizeOverflow)?;
    let base_addr = VirtAddr::new(base_value);
    if !is_mapped(base_addr, segments) {
        return Err(LinuxLoadError::RelocationTargetOutOfRange);
    }
    Ok(base_value as u64)
}

fn resolve_symbol_reloc(
    base: VirtAddr,
    reloc_type: u32,
    sym: u32,
    addend: i64,
    segments: &[MappedSegment],
) -> Result<u64, LinuxLoadError> {
    // Symbol resolution is not implemented yet; only RELATIVE/RELR are supported.
    if sym != 0 {
        return Err(LinuxLoadError::UnsupportedRelocation(reloc_type));
    }
    match reloc_type {
        R_X86_64_RELATIVE => resolve_relative_value(base, addend, segments),
        _ => Err(LinuxLoadError::UnsupportedRelocation(reloc_type)),
    }
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
    crate::println!(
        "[loader] relro range={:#x}-{:#x}",
        relro_start.as_raw(),
        relro_end.as_raw()
    );
    let page_size = segments
        .first()
        .map(|seg| seg.page_size)
        .unwrap_or(PageSize::SIZE_4K.bytes());
    let start = align_down(relro_start.as_raw(), page_size);
    let end = align_up(relro_end.as_raw(), page_size);

    // Apply RELRO at page granularity: any overlapping page becomes read-only.
    for addr in (start..end).step_by(page_size) {
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

#[repr(C)]
struct Elf64Rel {
    _offset: u64,
    _info: u64,
}
