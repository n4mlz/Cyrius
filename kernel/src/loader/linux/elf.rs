use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::convert::TryFrom;
use core::mem::size_of;

use crate::arch::api::ArchLinuxElfPlatform;
use crate::mem::addr::VirtAddr;

use super::LinuxLoadError;

pub(crate) const ELF_MAGIC: &[u8; 4] = b"\x7FELF";
pub(crate) const ELF_CLASS_64: u8 = 2;
pub(crate) const ELF_DATA_LSB: u8 = 1;
pub(crate) const ELF_VERSION_CURRENT: u8 = 1;
pub(crate) const ELF_TYPE_EXEC: u16 = 2;
pub(crate) const ELF_TYPE_DYN: u16 = 3;
pub(crate) const PT_LOAD: u32 = 1;
pub(crate) const PT_DYNAMIC: u32 = 2;
pub(crate) const PT_INTERP: u32 = 3;
pub(crate) const PT_PHDR: u32 = 6;
pub(crate) const PT_GNU_RELRO: u32 = 0x6474_e552;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ElfType {
    Exec,
    Dyn,
}

pub struct ElfFile {
    pub entry: VirtAddr,
    pub segments: Vec<ProgramSegment>,
    pub elf_type: ElfType,
    pub ph_offset: usize,
    pub ph_entry_size: u16,
    pub ph_count: u16,
    pub dynamic: Option<DynamicSegment>,
    pub relro: Option<RelroSegment>,
    pub phdr_vaddr: Option<VirtAddr>,
    pub interp: Option<String>,
}

pub struct ProgramSegment {
    pub flags: u32,
    pub offset: usize,
    pub vaddr: VirtAddr,
    pub file_size: usize,
    pub mem_size: usize,
}

pub struct DynamicSegment {
    pub vaddr: VirtAddr,
    pub mem_size: usize,
}

pub struct RelroSegment {
    pub vaddr: VirtAddr,
    pub mem_size: usize,
}

impl ElfFile {
    pub fn parse<P: ArchLinuxElfPlatform>(bytes: &[u8]) -> Result<Self, LinuxLoadError> {
        let header = ElfHeader::parse::<P>(bytes)?;
        let mut segments = Vec::new();
        let mut dynamic = None;
        let mut relro = None;
        let mut phdr_vaddr = None;
        let mut interp = None;
        let phoff = usize::try_from(header.ph_offset).map_err(|_| LinuxLoadError::SizeOverflow)?;
        let ent_size = usize::from(header.ph_entry_size);
        let count = usize::from(header.ph_count);

        for idx in 0..count {
            let start = phoff
                .checked_add(idx * ent_size)
                .ok_or(LinuxLoadError::SizeOverflow)?;
            let end = start
                .checked_add(ent_size)
                .ok_or(LinuxLoadError::SizeOverflow)?;
            let ph_slice = bytes
                .get(start..end)
                .ok_or(LinuxLoadError::InvalidElf("program header out of range"))?;
            let ph = ProgramHeader::parse(ph_slice)?;
            if ph.typ == PT_LOAD {
                segments.push(ProgramSegment {
                    flags: ph.flags,
                    offset: usize::try_from(ph.offset).map_err(|_| LinuxLoadError::SizeOverflow)?,
                    vaddr: VirtAddr::new(
                        usize::try_from(ph.vaddr).map_err(|_| LinuxLoadError::SizeOverflow)?,
                    ),
                    file_size: usize::try_from(ph.file_size)
                        .map_err(|_| LinuxLoadError::SizeOverflow)?,
                    mem_size: usize::try_from(ph.mem_size)
                        .map_err(|_| LinuxLoadError::SizeOverflow)?,
                });
            } else if ph.typ == PT_DYNAMIC {
                dynamic = Some(DynamicSegment {
                    vaddr: VirtAddr::new(
                        usize::try_from(ph.vaddr).map_err(|_| LinuxLoadError::SizeOverflow)?,
                    ),
                    mem_size: usize::try_from(ph.mem_size)
                        .map_err(|_| LinuxLoadError::SizeOverflow)?,
                });
            } else if ph.typ == PT_GNU_RELRO {
                relro = Some(RelroSegment {
                    vaddr: VirtAddr::new(
                        usize::try_from(ph.vaddr).map_err(|_| LinuxLoadError::SizeOverflow)?,
                    ),
                    mem_size: usize::try_from(ph.mem_size)
                        .map_err(|_| LinuxLoadError::SizeOverflow)?,
                });
            } else if ph.typ == PT_INTERP {
                let offset =
                    usize::try_from(ph.offset).map_err(|_| LinuxLoadError::SizeOverflow)?;
                let size =
                    usize::try_from(ph.file_size).map_err(|_| LinuxLoadError::SizeOverflow)?;
                let end = offset
                    .checked_add(size)
                    .ok_or(LinuxLoadError::SizeOverflow)?;
                let slice = bytes
                    .get(offset..end)
                    .ok_or(LinuxLoadError::InvalidElf("interp segment out of range"))?;
                let len = slice.iter().position(|b| *b == 0).unwrap_or(slice.len());
                interp = Some(
                    core::str::from_utf8(&slice[..len])
                        .map_err(|_| LinuxLoadError::InvalidElf("interp not utf-8"))?
                        .to_string(),
                );
            } else if ph.typ == PT_PHDR {
                phdr_vaddr = Some(VirtAddr::new(
                    usize::try_from(ph.vaddr).map_err(|_| LinuxLoadError::SizeOverflow)?,
                ));
            }
        }

        Ok(Self {
            entry: VirtAddr::new(
                usize::try_from(header.entry).map_err(|_| LinuxLoadError::SizeOverflow)?,
            ),
            segments,
            elf_type: header.elf_type,
            ph_offset: phoff,
            ph_entry_size: header.ph_entry_size,
            ph_count: header.ph_count,
            dynamic,
            relro,
            phdr_vaddr,
            interp,
        })
    }
}

struct ElfHeader {
    entry: u64,
    ph_offset: u64,
    ph_entry_size: u16,
    ph_count: u16,
    elf_type: ElfType,
}

impl ElfHeader {
    fn parse<P: ArchLinuxElfPlatform>(bytes: &[u8]) -> Result<Self, LinuxLoadError> {
        if bytes.len() < 64 {
            return Err(LinuxLoadError::InvalidElf("file too small"));
        }
        if &bytes[0..4] != ELF_MAGIC {
            return Err(LinuxLoadError::InvalidElf("bad magic"));
        }
        if bytes[4] != ELF_CLASS_64 {
            return Err(LinuxLoadError::InvalidElf("unsupported class"));
        }
        if bytes[5] != ELF_DATA_LSB {
            return Err(LinuxLoadError::InvalidElf("unsupported endianness"));
        }
        if bytes[6] != ELF_VERSION_CURRENT {
            return Err(LinuxLoadError::InvalidElf("unsupported version"));
        }
        let e_type = u16::from_le_bytes([bytes[16], bytes[17]]);
        let e_machine = u16::from_le_bytes([bytes[18], bytes[19]]);
        let elf_type = match e_type {
            ELF_TYPE_EXEC => ElfType::Exec,
            ELF_TYPE_DYN => ElfType::Dyn,
            _ => return Err(LinuxLoadError::InvalidElf("unsupported type")),
        };
        if e_machine != P::machine_id() {
            return Err(LinuxLoadError::InvalidElf("unsupported machine"));
        }
        let entry = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        let ph_offset = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        let ph_entry_size = u16::from_le_bytes(bytes[54..56].try_into().unwrap());
        let ph_count = u16::from_le_bytes(bytes[56..58].try_into().unwrap());
        if ph_entry_size as usize != size_of::<ProgramHeaderRaw>() {
            return Err(LinuxLoadError::InvalidElf("unexpected program header size"));
        }

        Ok(Self {
            entry,
            ph_offset,
            ph_entry_size,
            ph_count,
            elf_type,
        })
    }
}

pub(crate) struct ProgramHeaderRaw {
    pub(crate) typ: u32,
    pub(crate) flags: u32,
    pub(crate) offset: u64,
    pub(crate) vaddr: u64,
    pub(crate) _paddr: u64,
    pub(crate) file_size: u64,
    pub(crate) mem_size: u64,
    pub(crate) align: u64,
}

struct ProgramHeader {
    typ: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    file_size: u64,
    mem_size: u64,
    #[allow(dead_code)]
    align: u64,
}

impl ProgramHeader {
    fn parse(bytes: &[u8]) -> Result<Self, LinuxLoadError> {
        if bytes.len() < size_of::<ProgramHeaderRaw>() {
            return Err(LinuxLoadError::InvalidElf("truncated program header"));
        }
        let raw = ProgramHeaderRaw {
            typ: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            flags: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            offset: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            vaddr: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            _paddr: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
            file_size: u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
            mem_size: u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
            align: u64::from_le_bytes(bytes[48..56].try_into().unwrap()),
        };

        if raw.mem_size < raw.file_size {
            return Err(LinuxLoadError::InvalidElf("memsz < filesz"));
        }
        if raw.align != 0 && !raw.align.is_power_of_two() {
            return Err(LinuxLoadError::InvalidElf("p_align must be power of two"));
        }
        if raw.align != 0 && (raw.vaddr % raw.align) != (raw.offset % raw.align) {
            return Err(LinuxLoadError::AlignmentMismatch);
        }

        Ok(Self {
            typ: raw.typ,
            flags: raw.flags,
            offset: raw.offset,
            vaddr: raw.vaddr,
            file_size: raw.file_size,
            mem_size: raw.mem_size,
            align: raw.align,
        })
    }
}
