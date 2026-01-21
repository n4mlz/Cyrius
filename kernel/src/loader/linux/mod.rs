use crate::arch::api::ArchLinuxElfPlatform;
use crate::fs::{VfsError, VfsPath};
use crate::loader::DefaultLinuxElfPlatform;
use crate::mem::addr::{VirtAddr, align_up};
use crate::mem::paging::MapError;
use crate::process::fs as proc_fs;
use crate::process::{PROCESS_TABLE, ProcessError, ProcessId};

mod elf;
mod map;
mod patch;
mod stack;

pub use stack::{
    AuxvEntry, StackBuildError, initialise_minimal_stack, initialise_stack_with_args,
    initialise_stack_with_args_in_table,
};

/// Linux ELF image loaded into a process address space.
pub struct LinuxProgram<S> {
    pub entry: VirtAddr,
    pub user_stack: S,
    pub stack_pointer: VirtAddr,
    pub heap_base: VirtAddr,
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
    StackBuild(StackBuildError),
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

impl From<StackBuildError> for LinuxLoadError {
    fn from(err: StackBuildError) -> Self {
        Self::StackBuild(err)
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
    let elf_bytes = proc_fs::read_to_end_at(pid, &abs)?;
    let elf = elf::ElfFile::parse::<P>(&elf_bytes)?;

    let space: P::AddressSpace = PROCESS_TABLE
        .address_space(pid)
        .ok_or(LinuxLoadError::Process(ProcessError::NotFound))?;

    map::map_segments::<P>(&space, &elf, &elf_bytes)?;

    let user_stack = P::allocate_user_stack(&space, 32 * 1024)?;
    let stack_top = P::user_stack_top(&user_stack);
    let stack_pointer = space
        .with_page_table(|table, _| stack::initialise_minimal_stack(table, stack_top))
        .map_err(LinuxLoadError::from)?;
    let heap_base = compute_heap_base::<P>(&elf)?;

    Ok(LinuxProgram {
        entry: elf.entry,
        user_stack,
        stack_pointer,
        heap_base,
    })
}

fn resolve_path(pid: ProcessId, raw: &str) -> Result<VfsPath, LinuxLoadError> {
    let cwd = proc_fs::cwd(pid)?;
    VfsPath::resolve(raw, &cwd).map_err(LinuxLoadError::from)
}

fn compute_heap_base<P: ArchLinuxElfPlatform>(
    elf: &elf::ElfFile,
) -> Result<VirtAddr, LinuxLoadError> {
    let mut max_end = 0usize;
    for seg in &elf.segments {
        let end = seg
            .vaddr
            .as_raw()
            .checked_add(seg.mem_size)
            .ok_or(LinuxLoadError::SizeOverflow)?;
        if end > max_end {
            max_end = end;
        }
    }
    let aligned = align_up(max_end, P::page_size());
    Ok(VirtAddr::new(aligned))
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::arch::{
        Arch,
        api::{ArchPageTableAccess, ArchThread},
    };
    use crate::fs::{Directory, memfs::MemDirectory};
    use crate::mem::addr::{Addr, VirtIntoPtr};
    use crate::mem::paging::{MapError, PageTableOps, PhysMapper};
    use crate::println;
    use crate::test::kernel_test_case;

    use super::elf::{
        ELF_CLASS_64, ELF_DATA_LSB, ELF_MAGIC, ELF_TYPE_EXEC, ELF_VERSION_CURRENT, PT_LOAD,
        ProgramHeaderRaw,
    };
    use super::*;
    use core::mem::size_of;

    #[kernel_test_case]
    fn loads_minimal_static_elf() {
        println!("[test] loads_minimal_static_elf");

        let _ = PROCESS_TABLE.init_kernel();
        let pid = PROCESS_TABLE
            .create_user_process("linux-proc", crate::process::ProcessDomain::Host)
            .expect("create user process");

        let root = MemDirectory::new();
        crate::fs::force_replace_root(root.clone());

        let elf = test_elf_image();
        let file = root.create_file("demo").expect("create file");
        let _ = file.write_at(0, &elf).expect("write image");

        let program = load_elf(pid, "/demo").expect("load ELF");
        assert_eq!(program.entry.as_raw(), 0x400080);
        assert_eq!(program.heap_base.as_raw(), 0x402000);
        let space = PROCESS_TABLE
            .address_space(pid)
            .expect("user address space");
        let first = read_user_byte(&space, program.entry).expect("read entry");
        let second = read_user_byte(&space, program.entry.checked_add(1).unwrap()).expect("read");
        assert_eq!(first, 0xCD);
        assert_eq!(second, 0x80);

        let bss_base = VirtAddr::new(0x401000 + 0x100);
        for i in 0..0x80 {
            let addr = bss_base.checked_add(i).unwrap();
            let byte = read_user_byte(&space, addr).expect("read bss");
            assert_eq!(byte, 0);
        }

        let stack_top = <Arch as ArchThread>::user_stack_top(&program.user_stack);
        assert!(program.stack_pointer.as_raw() < stack_top.as_raw());
    }

    fn read_user_byte(
        space: &<Arch as ArchThread>::AddressSpace,
        addr: VirtAddr,
    ) -> Result<u8, LinuxLoadError> {
        let mut out = Ok(0u8);
        space
            .with_page_table(|table, _| {
                if out.is_ok() {
                    let phys = table.translate(addr)?;
                    let mapper = crate::mem::manager::phys_mapper();
                    unsafe {
                        let ptr = mapper.phys_to_virt(phys).into_ptr();
                        out = Ok(core::ptr::read(ptr));
                    }
                }
                Ok::<(), LinuxLoadError>(())
            })
            .map_err(|_| LinuxLoadError::Map(MapError::NotMapped))?;
        out
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

        // Write code segment bytes.
        buf[0x1000..0x1000 + 0x200].fill(0x90);
        buf[0x1000 + 0x80..0x1000 + 0x80 + 2].copy_from_slice(&[0x0F, 0x05]);

        // Write data segment bytes.
        buf[0x2000..0x2000 + 0x100].fill(0xAA);

        buf
    }

    fn write_ph(slot: &mut [u8], ph: ProgramHeaderRaw) {
        slot[0..4].copy_from_slice(&ph.typ.to_le_bytes());
        slot[4..8].copy_from_slice(&ph.flags.to_le_bytes());
        slot[8..16].copy_from_slice(&ph.offset.to_le_bytes());
        slot[16..24].copy_from_slice(&ph.vaddr.to_le_bytes());
        slot[24..32].copy_from_slice(&ph._paddr.to_le_bytes());
        slot[32..40].copy_from_slice(&ph.file_size.to_le_bytes());
        slot[40..48].copy_from_slice(&ph.mem_size.to_le_bytes());
        slot[48..56].copy_from_slice(&ph.align.to_le_bytes());
    }
}
