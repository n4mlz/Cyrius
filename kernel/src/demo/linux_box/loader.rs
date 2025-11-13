use alloc::vec::Vec;
use core::{convert::TryFrom, mem::size_of};

use crate::arch::{
    Arch,
    api::{ArchThread, UserImageError, UserSegment},
};
use crate::mem::addr::{MemPerm, VirtAddr};
use crate::process::ProcessId;

const ELF_MAGIC: [u8; 4] = *b"\x7FELF";
const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LE: u8 = 1;
const ELF_CURRENT_VERSION: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 0x3E;
const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const ELF_HEADER_SIZE: usize = 64;
const ELF_PROGRAM_HEADER_SIZE: usize = 56;

#[derive(Debug)]
pub enum LoaderError {
    InvalidElf(&'static str),
    UnsupportedElf(&'static str),
    AddressOverflow,
    SegmentOutOfBounds,
    SegmentTooLarge,
    NoLoadableSegments,
    Image(UserImageError),
}

impl From<UserImageError> for LoaderError {
    fn from(err: UserImageError) -> Self {
        Self::Image(err)
    }
}

pub struct LoadedImage {
    entry: VirtAddr,
    image: <Arch as ArchThread>::UserImage,
}

impl LoadedImage {
    pub fn entry(&self) -> VirtAddr {
        self.entry
    }

    pub fn into_parts(self) -> (<Arch as ArchThread>::UserImage, VirtAddr) {
        (self.image, self.entry)
    }
}

pub fn load(
    _pid: ProcessId,
    space: &<Arch as ArchThread>::AddressSpace,
    payload: &[u8],
) -> Result<LoadedImage, LoaderError> {
    let parsed = parse_elf(payload)?;
    if parsed.segments.is_empty() {
        return Err(LoaderError::NoLoadableSegments);
    }

    let mut user_segments = Vec::with_capacity(parsed.segments.len());
    for seg in &parsed.segments {
        user_segments.push(UserSegment {
            base: seg.base,
            data: seg.data,
            mem_size: seg.mem_size,
            perms: perms_from_flags(seg.flags),
        });
    }

    let image = <Arch as ArchThread>::map_user_image(space, &user_segments, parsed.entry)?;
    Ok(LoadedImage {
        entry: parsed.entry,
        image,
    })
}

fn parse_elf(payload: &[u8]) -> Result<ParsedElf<'_>, LoaderError> {
    if payload.len() < ELF_HEADER_SIZE {
        return Err(LoaderError::InvalidElf("file too small"));
    }

    let header = parse_header(payload)?;
    let mut segments = Vec::new();

    let program_headers = parse_program_headers(payload, &header)?;
    for ph in program_headers {
        if ph.typ != PT_LOAD || ph.mem_size == 0 {
            continue;
        }
        if ph.mem_size < ph.file_size {
            return Err(LoaderError::InvalidElf("segment memsz < filesz"));
        }

        let offset = usize::try_from(ph.offset).map_err(|_| LoaderError::SegmentTooLarge)?;
        let file_size = usize::try_from(ph.file_size).map_err(|_| LoaderError::SegmentTooLarge)?;
        let mem_size = usize::try_from(ph.mem_size).map_err(|_| LoaderError::SegmentTooLarge)?;
        let end = offset
            .checked_add(file_size)
            .ok_or(LoaderError::SegmentOutOfBounds)?;
        if end > payload.len() {
            return Err(LoaderError::SegmentOutOfBounds);
        }

        let base = usize::try_from(ph.vaddr).map_err(|_| LoaderError::AddressOverflow)?;
        segments.push(ElfLoadSegment {
            base: VirtAddr::new(base),
            mem_size,
            data: &payload[offset..end],
            flags: ph.flags,
        });
    }

    if segments.is_empty() {
        return Err(LoaderError::NoLoadableSegments);
    }

    let entry = usize::try_from(header.entry).map_err(|_| LoaderError::AddressOverflow)?;
    Ok(ParsedElf {
        entry: VirtAddr::new(entry),
        segments,
    })
}

fn parse_program_headers(
    payload: &[u8],
    header: &Elf64Header,
) -> Result<Vec<ElfProgramHeader>, LoaderError> {
    if header.program_entry_size != ELF_PROGRAM_HEADER_SIZE as u16 {
        return Err(LoaderError::UnsupportedElf("unexpected ph size"));
    }

    let count = usize::try_from(header.program_count).map_err(|_| LoaderError::SegmentTooLarge)?;
    let phoff = usize::try_from(header.program_offset).map_err(|_| LoaderError::SegmentTooLarge)?;

    let table_size = header
        .program_entry_size
        .checked_mul(header.program_count)
        .ok_or(LoaderError::SegmentTooLarge)?;
    let table_size = usize::try_from(table_size).map_err(|_| LoaderError::SegmentTooLarge)?;
    let table_end = phoff
        .checked_add(table_size)
        .ok_or(LoaderError::SegmentOutOfBounds)?;
    if table_end > payload.len() {
        return Err(LoaderError::SegmentOutOfBounds);
    }

    let mut headers = Vec::with_capacity(count);
    for i in 0..count {
        let offset = phoff
            .checked_add(i * ELF_PROGRAM_HEADER_SIZE)
            .ok_or(LoaderError::SegmentOutOfBounds)?;
        let end = offset + ELF_PROGRAM_HEADER_SIZE;
        let entry = &payload[offset..end];
        headers.push(parse_program_header(entry));
    }

    Ok(headers)
}

fn parse_header(payload: &[u8]) -> Result<Elf64Header, LoaderError> {
    if &payload[0..4] != ELF_MAGIC {
        return Err(LoaderError::InvalidElf("bad magic"));
    }
    if payload[4] != ELF_CLASS_64 {
        return Err(LoaderError::UnsupportedElf("non-ELF64 binary"));
    }
    if payload[5] != ELF_DATA_LE {
        return Err(LoaderError::UnsupportedElf("non little-endian binary"));
    }
    if payload[6] != ELF_CURRENT_VERSION {
        return Err(LoaderError::UnsupportedElf("unsupported ELF version"));
    }

    let ty = read_u16(payload, 16);
    if ty != ET_EXEC && ty != ET_DYN {
        return Err(LoaderError::UnsupportedElf("unsupported ELF type"));
    }
    let machine = read_u16(payload, 18);
    if machine != EM_X86_64 {
        return Err(LoaderError::UnsupportedElf("unsupported machine"));
    }

    let entry = read_u64(payload, 24);
    let program_offset = read_u64(payload, 32);
    let program_entry_size = read_u16(payload, 54);
    let program_count = read_u16(payload, 56);

    Ok(Elf64Header {
        entry,
        program_offset,
        program_entry_size,
        program_count,
    })
}

fn parse_program_header(bytes: &[u8]) -> ElfProgramHeader {
    ElfProgramHeader {
        typ: read_u32(bytes, 0),
        flags: read_u32(bytes, 4),
        offset: read_u64(bytes, 8),
        vaddr: read_u64(bytes, 16),
        file_size: read_u64(bytes, 32),
        mem_size: read_u64(bytes, 40),
    }
}

fn perms_from_flags(flags: u32) -> MemPerm {
    let mut perms = MemPerm::USER.union(MemPerm::READ);
    if flags & PF_X != 0 {
        perms = perms.union(MemPerm::EXEC);
    }
    if flags & PF_W != 0 {
        perms = perms.union(MemPerm::WRITE);
    }
    perms
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    let mut buf = [0u8; size_of::<u16>()];
    buf.copy_from_slice(&bytes[offset..offset + size_of::<u16>()]);
    u16::from_le_bytes(buf)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut buf = [0u8; size_of::<u32>()];
    buf.copy_from_slice(&bytes[offset..offset + size_of::<u32>()]);
    u32::from_le_bytes(buf)
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut buf = [0u8; size_of::<u64>()];
    buf.copy_from_slice(&bytes[offset..offset + size_of::<u64>()]);
    u64::from_le_bytes(buf)
}

#[derive(Debug)]
struct ParsedElf<'a> {
    entry: VirtAddr,
    segments: Vec<ElfLoadSegment<'a>>,
}

#[derive(Debug)]
struct ElfLoadSegment<'a> {
    base: VirtAddr,
    mem_size: usize,
    data: &'a [u8],
    flags: u32,
}

struct Elf64Header {
    entry: u64,
    program_offset: u64,
    program_entry_size: u16,
    program_count: u16,
}

struct ElfProgramHeader {
    typ: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    file_size: u64,
    mem_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::kernel_test_case;
    use alloc::{vec, vec::Vec};

    #[kernel_test_case]
    fn rejects_invalid_magic() {
        let data = [0u8; ELF_HEADER_SIZE];
        let err = parse_elf(&data).expect_err("invalid ELF should fail");
        assert!(matches!(err, LoaderError::InvalidElf(_)));
    }

    #[kernel_test_case]
    fn parses_single_load_segment() {
        let bytes = test_image();
        let image = parse_elf(&bytes).expect("parse elf");
        assert_eq!(image.entry.as_raw(), 0x401000);
        assert_eq!(image.segments.len(), 1);
        let seg = &image.segments[0];
        assert_eq!(seg.base.as_raw(), 0x401000);
        assert_eq!(seg.mem_size, 0x30);
        assert_eq!(seg.data, &[1, 2, 3, 4]);
        assert_eq!(perms_from_flags(PF_R | PF_X), MemPerm::USER_RX);
    }

    fn test_image() -> Vec<u8> {
        let data_offset = ELF_HEADER_SIZE + ELF_PROGRAM_HEADER_SIZE;
        let total_size = data_offset + 4;
        let mut buf = vec![0u8; total_size];
        buf[0..4].copy_from_slice(&ELF_MAGIC);
        buf[4] = ELF_CLASS_64;
        buf[5] = ELF_DATA_LE;
        buf[6] = ELF_CURRENT_VERSION;
        buf[7] = 0;
        write_u16(&mut buf, 16, ET_EXEC);
        write_u16(&mut buf, 18, EM_X86_64);
        write_u32(&mut buf, 20, 1);
        write_u64(&mut buf, 24, 0x401000);
        write_u64(&mut buf, 32, ELF_HEADER_SIZE as u64);
        write_u16(&mut buf, 54, ELF_PROGRAM_HEADER_SIZE as u16);
        write_u16(&mut buf, 56, 1);

        let ph_off = ELF_HEADER_SIZE;
        write_u32(&mut buf, ph_off + 0, PT_LOAD);
        write_u32(&mut buf, ph_off + 4, PF_R | PF_X);
        write_u64(&mut buf, ph_off + 8, data_offset as u64);
        write_u64(&mut buf, ph_off + 16, 0x401000);
        write_u64(&mut buf, ph_off + 32, 4);
        write_u64(&mut buf, ph_off + 40, 0x30);
        write_u64(&mut buf, ph_off + 48, 0x1000);

        buf[data_offset..data_offset + 4].copy_from_slice(&[1, 2, 3, 4]);
        buf
    }

    fn write_u16(buf: &mut [u8], offset: usize, value: u16) {
        buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(buf: &mut [u8], offset: usize, value: u64) {
        buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
}
