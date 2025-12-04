use alloc::{vec, vec::Vec};
use core::convert::TryFrom;
use core::mem::size_of;

use crate::arch::api::{ArchLinuxElfPlatform, ArchPageTableAccess};
use crate::fs::{NodeRef, VfsError, VfsPath, with_vfs};
use crate::loader::DefaultLinuxElfPlatform;
use crate::mem::addr::{MemPerm, Page, PageSize, VirtAddr, VirtIntoPtr};
use crate::mem::paging::{FrameAllocator, MapError, PageTableOps};
use crate::process::{PROCESS_TABLE, ProcessError, ProcessId};

const ELF_MAGIC: &[u8; 4] = b"\x7FELF";
const ELF_CLASS_64: u8 = 2;
const ELF_DATA_LSB: u8 = 1;
const ELF_VERSION_CURRENT: u8 = 1;
const ELF_TYPE_EXEC: u16 = 2;
const PT_LOAD: u32 = 1;

const DEFAULT_STACK_SIZE: usize = 32 * 1024;

/// Linux ELF image loaded into a process address space.
pub struct LinuxProgram<S> {
    pub entry: VirtAddr,
    pub user_stack: S,
    pub stack_pointer: VirtAddr,
}

#[derive(Debug)]
pub enum LinuxLoadError {
    Process(ProcessError),
    Vfs(VfsError),
    InvalidElf(&'static str),
    Map(MapError),
    FrameAllocationFailed,
    SizeOverflow,
    UserStack(crate::arch::api::UserStackError),
    NotFound,
    AlignmentMismatch,
}

impl From<ProcessError> for LinuxLoadError {
    fn from(err: ProcessError) -> Self {
        Self::Process(err)
    }
}

impl From<VfsError> for LinuxLoadError {
    fn from(err: VfsError) -> Self {
        Self::Vfs(err)
    }
}

impl From<MapError> for LinuxLoadError {
    fn from(err: MapError) -> Self {
        Self::Map(err)
    }
}

impl From<crate::arch::api::UserStackError> for LinuxLoadError {
    fn from(err: crate::arch::api::UserStackError) -> Self {
        Self::UserStack(err)
    }
}

/// Load a static, non-PIE 64-bit ELF into the target process address space.
pub fn load_elf(
    pid: ProcessId,
    raw_path: &str,
) -> Result<
    LinuxProgram<<DefaultLinuxElfPlatform as ArchLinuxElfPlatform>::UserStack>,
    LinuxLoadError,
> {
    load_elf_with_platform::<DefaultLinuxElfPlatform>(pid, raw_path)
}

pub fn load_elf_with_platform<P>(
    pid: ProcessId,
    raw_path: &str,
) -> Result<LinuxProgram<P::UserStack>, LinuxLoadError>
where
    P: ArchLinuxElfPlatform<AddressSpace = crate::arch::x86_64::AddressSpace>,
{
    let abs = resolve_path(pid, raw_path)?;
    let elf_bytes = read_file(&abs)?;
    let elf = ElfFile::parse::<P>(&elf_bytes)?;

    let space: P::AddressSpace = PROCESS_TABLE
        .address_space(pid)
        .ok_or(LinuxLoadError::Process(ProcessError::NotFound))?;

    map_segments::<P>(&space, &elf, &elf_bytes)?;

    let user_stack = P::allocate_user_stack(&space, DEFAULT_STACK_SIZE)?;
    let stack_top = P::user_stack_top(&user_stack);
    let stack_pointer = initialise_minimal_stack(stack_top);

    Ok(LinuxProgram {
        entry: elf.entry,
        user_stack,
        stack_pointer,
    })
}

fn resolve_path(pid: ProcessId, raw: &str) -> Result<VfsPath, LinuxLoadError> {
    let cwd = PROCESS_TABLE.cwd(pid)?;
    let parsed = VfsPath::parse(raw)?;
    if parsed.is_absolute() {
        Ok(parsed)
    } else {
        cwd.join(&parsed).map_err(LinuxLoadError::from)
    }
}

fn read_file(path: &VfsPath) -> Result<Vec<u8>, LinuxLoadError> {
    let node = with_vfs(|vfs| vfs.open_absolute(path))?;
    match node {
        NodeRef::File(file) => {
            let meta = file.metadata()?;
            let size = usize::try_from(meta.size).map_err(|_| LinuxLoadError::SizeOverflow)?;
            let mut buf = vec![0u8; size];
            let read = file.read_at(0, &mut buf)?;
            if read != size {
                return Err(LinuxLoadError::InvalidElf(
                    "short read (regular file expected)",
                ));
            }
            Ok(buf)
        }
        NodeRef::Directory(_) => Err(LinuxLoadError::InvalidElf("path is a directory")),
    }
}

fn map_segments<P: ArchLinuxElfPlatform>(
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

fn initialise_minimal_stack(stack_top: VirtAddr) -> VirtAddr {
    let mut sp = align_down(stack_top.as_raw(), 16);

    // auxv terminator
    sp -= size_of::<u64>();
    unsafe { *(sp as *mut u64) = 0 };
    sp -= size_of::<u64>();
    unsafe { *(sp as *mut u64) = 0 };

    // envp null
    sp -= size_of::<u64>();
    unsafe { *(sp as *mut u64) = 0 };

    // argv null
    sp -= size_of::<u64>();
    unsafe { *(sp as *mut u64) = 0 };

    // argc = 0
    sp -= size_of::<u64>();
    unsafe { *(sp as *mut u64) = 0 };

    VirtAddr::new(sp)
}

/// Translate Linux `syscall` instructions to `int 0x80` so we can reuse the existing software
/// interrupt handler until `SYSCALL/SYSRET` is wired up.
fn rewrite_syscalls(seg: &ProgramSegment) {
    let mut offset = 0usize;
    while offset + 1 < seg.file_size {
        let ptr = unsafe { seg.vaddr.into_mut_ptr().add(offset) };
        let opcode = unsafe { core::ptr::read(ptr) };
        let next = unsafe { core::ptr::read(ptr.add(1)) };
        if opcode == 0x0F && next == 0x05 {
            unsafe {
                core::ptr::write(ptr, 0xCD);
                core::ptr::write(ptr.add(1), 0x80);
            }
        }
        offset = offset.saturating_add(1);
    }
}

fn align_down(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    value & !(align - 1)
}

fn align_up(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two());
    (value + (align - 1)) & !(align - 1)
}

struct ElfFile {
    entry: VirtAddr,
    segments: Vec<ProgramSegment>,
}

struct ProgramSegment {
    flags: u32,
    offset: usize,
    vaddr: VirtAddr,
    file_size: usize,
    mem_size: usize,
}

impl ElfFile {
    fn parse<P: ArchLinuxElfPlatform>(bytes: &[u8]) -> Result<Self, LinuxLoadError> {
        let header = ElfHeader::parse::<P>(bytes)?;
        let mut segments = Vec::new();
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
            }
        }

        Ok(Self {
            entry: VirtAddr::new(
                usize::try_from(header.entry).map_err(|_| LinuxLoadError::SizeOverflow)?,
            ),
            segments,
        })
    }
}

struct ElfHeader {
    entry: u64,
    ph_offset: u64,
    ph_entry_size: u16,
    ph_count: u16,
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
        if e_type != ELF_TYPE_EXEC {
            return Err(LinuxLoadError::InvalidElf("unsupported type"));
        }
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
        })
    }
}

struct ProgramHeaderRaw {
    typ: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    _paddr: u64,
    file_size: u64,
    mem_size: u64,
    align: u64,
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

#[cfg(test)]
mod tests {
    use alloc::vec;

    use crate::arch::{Arch, api::ArchThread};
    use crate::fs::{Directory, memfs::MemDirectory};
    use crate::mem::addr::VirtIntoPtr;
    use crate::println;
    use crate::test::kernel_test_case;

    use super::*;

    #[kernel_test_case]
    fn loads_minimal_static_elf() {
        println!("[test] loads_minimal_static_elf");

        let _ = PROCESS_TABLE.init_kernel();
        let pid = PROCESS_TABLE
            .create_user_process("linux-proc")
            .expect("create user process");

        let root = MemDirectory::new();
        crate::fs::force_replace_root(root.clone());

        let elf = test_elf_image();
        let file = root.create_file("demo").expect("create file");
        let _ = file.write_at(0, &elf).expect("write image");

        let program = load_elf(pid, "/demo").expect("load ELF");
        assert_eq!(program.entry.as_raw(), 0x400080);
        unsafe {
            let first = core::ptr::read(program.entry.into_ptr());
            let second = core::ptr::read(program.entry.into_ptr().add(1));
            assert_eq!(first, 0xCD);
            assert_eq!(second, 0x80);
        }

        unsafe {
            let bss_base = (0x401000 + 0x100) as *const u8;
            for i in 0..0x80 {
                assert_eq!(*bss_base.add(i), 0);
            }
        }

        let stack_top = <Arch as ArchThread>::user_stack_top(&program.user_stack);
        assert!(program.stack_pointer.as_raw() < stack_top.as_raw());
    }

    fn test_elf_image() -> Vec<u8> {
        let mut buf = vec![0u8; 0x2000 + 0x200];

        // ELF header
        buf[0..4].copy_from_slice(ELF_MAGIC);
        buf[4] = ELF_CLASS_64;
        buf[5] = ELF_DATA_LSB;
        buf[6] = ELF_VERSION_CURRENT;
        buf[16..18].copy_from_slice(&ELF_TYPE_EXEC.to_le_bytes());
        buf[18..20].copy_from_slice(&DefaultLinuxElfPlatform::machine_id().to_le_bytes());
        buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
        buf[24..32].copy_from_slice(&(0x400080u64).to_le_bytes()); // e_entry
        buf[32..40].copy_from_slice(&(64u64).to_le_bytes()); // e_phoff
        buf[54..56].copy_from_slice(&(size_of::<ProgramHeaderRaw>() as u16).to_le_bytes());
        buf[56..58].copy_from_slice(&(2u16).to_le_bytes()); // phnum

        // Program header #0 (text)
        write_ph(
            &mut buf[64..64 + size_of::<ProgramHeaderRaw>()],
            ProgramHeaderRaw {
                typ: PT_LOAD,
                flags: 0x5,
                offset: 0x1000,
                vaddr: 0x400000,
                _paddr: 0,
                file_size: 0x200,
                mem_size: 0x200,
                align: 0x1000,
            },
        );

        // Program header #1 (data + bss)
        write_ph(
            &mut buf[64 + size_of::<ProgramHeaderRaw>()..64 + 2 * size_of::<ProgramHeaderRaw>()],
            ProgramHeaderRaw {
                typ: PT_LOAD,
                flags: 0x6,
                offset: 0x2000,
                vaddr: 0x401000,
                _paddr: 0,
                file_size: 0x100,
                mem_size: 0x180,
                align: 0x1000,
            },
        );

        // Text contents (align entry point at 0x400080)
        buf[0x1000 + 0x80] = 0x0F;
        buf[0x1000 + 0x81] = 0x05;

        // Data contents
        buf[0x2000] = 0x11;
        buf[0x2001] = 0x22;

        buf
    }

    fn write_ph(dst: &mut [u8], ph: ProgramHeaderRaw) {
        dst[0..4].copy_from_slice(&ph.typ.to_le_bytes());
        dst[4..8].copy_from_slice(&ph.flags.to_le_bytes());
        dst[8..16].copy_from_slice(&ph.offset.to_le_bytes());
        dst[16..24].copy_from_slice(&ph.vaddr.to_le_bytes());
        dst[24..32].copy_from_slice(&ph._paddr.to_le_bytes());
        dst[32..40].copy_from_slice(&ph.file_size.to_le_bytes());
        dst[40..48].copy_from_slice(&ph.mem_size.to_le_bytes());
        dst[48..56].copy_from_slice(&ph.align.to_le_bytes());
    }
}
