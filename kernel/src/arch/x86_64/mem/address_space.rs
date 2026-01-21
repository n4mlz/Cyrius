use alloc::sync::Arc;
use core::convert::TryFrom;

use x86_64::{
    registers::control::{Cr3, Cr3Flags},
    structures::paging::PhysFrame,
};

use crate::mem::addr::{Page, PageSize, PhysAddr, align_up};
use crate::mem::frame::FrameAllocatorGuard;
use crate::mem::manager;
use crate::mem::mapper::OffsetMapper;
use crate::mem::paging::FrameAllocator;
use crate::util::{lazylock::LazyLock, spinlock::SpinLock};

use super::paging::X86PageTable;

pub struct AddressSpace {
    root: Page<PhysAddr>,
    flags: Cr3Flags,
    owned_root: bool,
    lock: SpinLock<()>,
    user_stack_allocator: SpinLock<UserStackAllocator>,
}

impl AddressSpace {
    fn new(root: Page<PhysAddr>, flags: Cr3Flags, owned_root: bool) -> Self {
        Self {
            root,
            flags,
            owned_root,
            lock: SpinLock::new(()),
            user_stack_allocator: SpinLock::new(UserStackAllocator::new()),
        }
    }

    pub fn root_frame(&self) -> Page<PhysAddr> {
        self.root
    }

    pub fn cr3_flags(&self) -> Cr3Flags {
        self.flags
    }

    /// Load this address space's root page table into `CR3`.
    ///
    /// # Safety
    /// The caller must ensure that `self` represents a valid address space whose
    /// root table remains resident and exclusively owned for the duration of the
    /// switch. Interrupt handlers and concurrent cores must not mutate the same
    /// page tables while the transition is in progress.
    pub unsafe fn activate(&self) {
        let frame = phys_frame_from_page(self.root);
        unsafe { Cr3::write(frame, self.flags) };
    }

    /// Execute `f` with exclusive access to the root page table and frame allocator.
    ///
    /// # Implicit Contract
    /// - Global memory services must be initialised via `mem::manager::init` before calling this.
    pub fn with_table<F, R>(&self, mut f: F) -> R
    where
        F: FnMut(&mut X86PageTable<OffsetMapper>, &mut FrameAllocatorGuard<'_>) -> R,
    {
        let _guard = self.lock.lock();
        let mapper = manager::phys_mapper();
        let mut table = unsafe { X86PageTable::from_existing(self.root, mapper) };
        let mut allocator = manager::frame_allocator();
        f(&mut table, &mut allocator)
    }

    pub fn allocate_user_stack_region(
        &self,
        size: usize,
    ) -> Result<(usize, usize), crate::arch::api::UserStackError> {
        if size == 0 {
            return Err(crate::arch::api::UserStackError::InvalidSize);
        }
        let aligned = align_up(size, USER_STACK_ALIGNMENT);
        let base = {
            let mut allocator = self.user_stack_allocator.lock();
            allocator
                .allocate(aligned)
                .ok_or(crate::arch::api::UserStackError::AddressSpaceExhausted)?
        };
        Ok((base, aligned))
    }

    pub fn deallocate_user_stack_region(&self, base: usize, size: usize) {
        let mut allocator = self.user_stack_allocator.lock();
        allocator.deallocate(base, size);
    }

    pub fn reserve_user_stack_region(
        &self,
        base: usize,
        size: usize,
    ) -> Result<(), crate::arch::api::UserStackError> {
        let mut allocator = self.user_stack_allocator.lock();
        allocator.reserve(base, size)
    }

    fn reset_user_stack_allocator(&self) {
        let mut allocator = self.user_stack_allocator.lock();
        *allocator = UserStackAllocator::new();
    }
}

impl Drop for AddressSpace {
    fn drop(&mut self) {
        if self.owned_root {
            let mut allocator = manager::frame_allocator();
            allocator.deallocate(self.root);
        }
    }
}

#[derive(Debug)]
pub enum AddressSpaceError {
    FrameAllocationFailed,
    MapFailed(crate::mem::paging::MapError),
    UnsupportedMapping,
}

impl From<crate::arch::x86_64::mem::paging::UserMappingError> for AddressSpaceError {
    fn from(err: crate::arch::x86_64::mem::paging::UserMappingError) -> Self {
        match err {
            crate::arch::x86_64::mem::paging::UserMappingError::FrameAllocationFailed => {
                AddressSpaceError::FrameAllocationFailed
            }
            crate::arch::x86_64::mem::paging::UserMappingError::UnsupportedHugePage => {
                AddressSpaceError::UnsupportedMapping
            }
        }
    }
}

impl From<crate::mem::paging::MapError> for AddressSpaceError {
    fn from(err: crate::mem::paging::MapError) -> Self {
        AddressSpaceError::MapFailed(err)
    }
}

/// Allocate a fresh address space with an empty root page table.
///
/// # Errors
/// Returns [`AddressSpaceError::FrameAllocationFailed`] if the global frame allocator cannot
/// supply an additional frame for the root table.
pub fn create_empty() -> Result<Arc<AddressSpace>, AddressSpaceError> {
    let mut allocator = manager::frame_allocator();
    let frame = allocator
        .allocate(PageSize::SIZE_4K)
        .ok_or(AddressSpaceError::FrameAllocationFailed)?;
    let mapper = manager::phys_mapper();
    unsafe { X86PageTable::new(frame, mapper) };

    let (_, flags) = Cr3::read();
    Ok(Arc::new(AddressSpace::new(frame, flags, true)))
}

/// Allocate a fresh user address space with kernel mappings copied in.
pub fn create_user_space() -> Result<Arc<AddressSpace>, AddressSpaceError> {
    let space = create_empty()?;
    let kernel = kernel_address_space();
    // Avoid nested with_table: FrameAllocatorGuard uses a global lock that is not re-entrant.
    let kernel_entries = kernel.with_table(|table, _| table.kernel_p4_entries());
    space.with_table(|dst_table, _| {
        dst_table.install_kernel_p4_entries(&kernel_entries);
    });
    Ok(space)
}

/// Clone the user portion of an existing address space into a new one.
pub fn clone_user_space(
    parent: &Arc<AddressSpace>,
) -> Result<Arc<AddressSpace>, AddressSpaceError> {
    let space = create_user_space()?;
    let mut result = Ok(());
    space.with_table(|dst_table, allocator| {
        parent.with_table(|src_table, _| {
            if result.is_ok() {
                result = dst_table
                    .clone_user_mappings_from(src_table, allocator)
                    .map_err(AddressSpaceError::from);
            }
        });
    });
    result?;
    Ok(space)
}

pub fn clear_user_mappings(space: &Arc<AddressSpace>) -> Result<(), AddressSpaceError> {
    let mut result = Ok(());
    space.with_table(|table, allocator| {
        if result.is_ok() {
            result = table
                .clear_user_mappings(allocator)
                .map_err(AddressSpaceError::from);
        }
    });
    if result.is_ok() {
        space.reset_user_stack_allocator();
    }
    result
}

/// Obtain a reference-counted handle to the kernel's current address space.
///
/// # Implicit Contract
/// - `mem::manager::init` must have been invoked so the physical mapper is available.
pub fn kernel_address_space() -> Arc<AddressSpace> {
    KERNEL_SPACE.get().clone()
}

static KERNEL_SPACE: LazyLock<Arc<AddressSpace>, fn() -> Arc<AddressSpace>> =
    LazyLock::new_const(init_kernel_space);

fn init_kernel_space() -> Arc<AddressSpace> {
    let (frame, flags) = Cr3::read();
    let phys = frame.start_address().as_u64();
    let addr = usize::try_from(phys).expect("CR3 frame exceeds usize range");
    let root = Page::new(PhysAddr::new(addr), PageSize::SIZE_4K);
    Arc::new(AddressSpace::new(root, flags, false))
}

const USER_STACK_REGION_START: usize = 0x0000_7000_0000_0000;
const USER_STACK_REGION_END: usize = 0x0000_7FFF_FF00_0000;
const USER_STACK_ALIGNMENT: usize = PageSize::SIZE_4K.bytes();

struct UserStackAllocator {
    next: usize,
    free: alloc::vec::Vec<(usize, usize)>,
}

impl UserStackAllocator {
    fn new() -> Self {
        Self {
            next: USER_STACK_REGION_END,
            free: alloc::vec::Vec::new(),
        }
    }

    fn allocate(&mut self, size: usize) -> Option<usize> {
        if let Some(index) = self
            .free
            .iter()
            .position(|(_, region_size)| *region_size == size)
        {
            let (base, _) = self.free.swap_remove(index);
            return Some(base);
        }

        if self.next < USER_STACK_REGION_START + size {
            return None;
        }

        self.next -= size;
        Some(self.next)
    }

    fn deallocate(&mut self, base: usize, size: usize) {
        self.free.push((base, size));
    }

    fn reserve(
        &mut self,
        base: usize,
        size: usize,
    ) -> Result<(), crate::arch::api::UserStackError> {
        if size == 0 {
            return Err(crate::arch::api::UserStackError::InvalidSize);
        }
        let aligned = align_up(size, USER_STACK_ALIGNMENT);
        if aligned != size {
            return Err(crate::arch::api::UserStackError::InvalidSize);
        }
        let end = base
            .checked_add(size)
            .ok_or(crate::arch::api::UserStackError::InvalidSize)?;
        if end != self.next {
            // Current allocator only supports reserving the most-recent region.
            return Err(crate::arch::api::UserStackError::AddressSpaceExhausted);
        }
        self.next = base;
        Ok(())
    }
}

fn phys_frame_from_page(page: Page<PhysAddr>) -> PhysFrame {
    let phys = x86_64::PhysAddr::new(page.start.as_raw() as u64);
    PhysFrame::from_start_address(phys).expect("root frame must be aligned")
}
