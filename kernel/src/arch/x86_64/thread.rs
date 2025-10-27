use alloc::{sync::Arc, vec::Vec};
use core::convert::TryFrom;

use crate::arch::x86_64::mem::address_space::{self, AddressSpace as InnerAddressSpace};
use crate::mem::addr::{Addr, MemPerm, Page, PageSize, VirtAddr, VirtIntoPtr};
use crate::mem::paging::{FrameAllocator, PageTableOps, UnmapError};
use crate::util::{lazylock::LazyLock, spinlock::SpinLock};

use super::trap::{GeneralRegisters, TrapFrame, gdt};

const STACK_ALIGNMENT: u64 = 16;
const RFLAGS_RESERVED: u64 = 1 << 1;
const RFLAGS_INTERRUPT_ENABLE: u64 = 1 << 9;
const USER_STACK_REGION_START: usize = 0x0000_7000_0000_0000;
const USER_STACK_REGION_END: usize = 0x0000_7FFF_FF00_0000;
const USER_STACK_ALIGNMENT: usize = PageSize::SIZE_4K.bytes();

struct UserStackAllocator {
    next: usize,
    free: Vec<(usize, usize)>,
}

impl UserStackAllocator {
    fn new() -> Self {
        Self {
            next: USER_STACK_REGION_END,
            free: Vec::new(),
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
}

fn user_stack_allocator() -> &'static SpinLock<UserStackAllocator> {
    fn init() -> SpinLock<UserStackAllocator> {
        SpinLock::new(UserStackAllocator::new())
    }

    static ALLOCATOR: LazyLock<SpinLock<UserStackAllocator>, fn() -> SpinLock<UserStackAllocator>> =
        LazyLock::new_const(init);
    &ALLOCATOR
}

#[derive(Clone)]
pub struct UserStack {
    space: AddressSpace,
    base: VirtAddr,
    size: usize,
}

impl UserStack {
    pub(crate) fn allocate(
        space: &AddressSpace,
        size: usize,
    ) -> Result<Self, crate::arch::api::UserStackError> {
        if size == 0 {
            return Err(crate::arch::api::UserStackError::InvalidSize);
        }

        let aligned = align_up_usize(size, USER_STACK_ALIGNMENT);
        let base = {
            let mut allocator = user_stack_allocator().lock();
            allocator
                .allocate(aligned)
                .ok_or(crate::arch::api::UserStackError::AddressSpaceExhausted)?
        };

        let virt_base = VirtAddr::new(base);
        let map_result = space.inner().with_table(|table, allocator| {
            let mut mapped_pages = Vec::new();
            for offset in (0..aligned).step_by(PageSize::SIZE_4K.bytes()) {
                let addr = VirtAddr::new(base + offset);
                let page = Page::new(addr, PageSize::SIZE_4K);
                let frame = allocator
                    .allocate(PageSize::SIZE_4K)
                    .ok_or(crate::arch::api::UserStackError::OutOfMemory)?;

                if let Err(err) = table.map(page, frame, MemPerm::USER_RW, allocator) {
                    allocator.deallocate(frame);
                    rollback_user_mapping(table, allocator, &mapped_pages);
                    return Err(crate::arch::api::UserStackError::MapFailed(err));
                }

                unsafe {
                    core::ptr::write_bytes(addr.into_mut_ptr(), 0, PageSize::SIZE_4K.bytes());
                }

                mapped_pages.push(addr);
            }
            Ok(())
        });

        if let Err(err) = map_result {
            user_stack_allocator().lock().deallocate(base, aligned);
            return Err(err);
        }

        Ok(Self {
            space: space.clone(),
            base: virt_base,
            size: aligned,
        })
    }

    pub(crate) fn top(&self) -> VirtAddr {
        self.base
            .checked_add(self.size)
            .expect("user stack top overflow")
    }
}

impl Drop for UserStack {
    fn drop(&mut self) {
        self.space.inner().with_table(|table, allocator| {
            for offset in (0..self.size).step_by(PageSize::SIZE_4K.bytes()) {
                let addr = self.base.as_raw() + offset;
                let page = Page::new(VirtAddr::new(addr), PageSize::SIZE_4K);
                match table.unmap(page) {
                    Ok(frame) => allocator.deallocate(frame),
                    Err(UnmapError::NotMapped) => {}
                    Err(err) => panic!("failed to unmap user stack page: {err:?}"),
                }
            }
        });

        user_stack_allocator()
            .lock()
            .deallocate(self.base.as_raw(), self.size);
    }
}

unsafe impl Send for UserStack {}

/// Saved CPU context for a suspended kernel thread.
#[derive(Clone)]
pub struct Context {
    regs: GeneralRegisters,
    rip: u64,
    rsp: u64,
    rflags: u64,
    cs: u64,
    ss: u64,
}

impl Context {
    pub fn from_trap(frame: &TrapFrame) -> Self {
        Self {
            regs: frame.regs,
            rip: frame.rip,
            rsp: frame.rsp,
            rflags: frame.rflags,
            cs: frame.cs,
            ss: frame.ss,
        }
    }

    pub fn write_to_trap(&self, frame: &mut TrapFrame) {
        frame.regs = self.regs;
        frame.rip = self.rip;
        frame.rsp = self.rsp;
        frame.rflags = self.rflags;
        frame.cs = self.cs;
        frame.ss = self.ss;
        frame.error_code = 0;
    }

    pub fn for_kernel(entry: VirtAddr, stack_top: VirtAddr) -> Self {
        let mut ctx = Self::empty();
        ctx.rip = virt_to_u64(entry);
        ctx.rsp = align_down_u64(virt_to_u64(stack_top), STACK_ALIGNMENT);
        ctx.rflags = RFLAGS_RESERVED | RFLAGS_INTERRUPT_ENABLE;

        let selectors = gdt::selectors();
        ctx.cs = selectors.kernel_code.0 as u64;
        ctx.ss = selectors.kernel_data.0 as u64;
        ctx
    }

    pub fn for_user(entry: VirtAddr, stack_top: VirtAddr) -> Self {
        let mut ctx = Self::empty();
        ctx.rip = virt_to_u64(entry);
        ctx.rsp = align_down_u64(virt_to_u64(stack_top), STACK_ALIGNMENT);
        ctx.rflags = RFLAGS_RESERVED | RFLAGS_INTERRUPT_ENABLE;

        let selectors = gdt::selectors();
        ctx.cs = selectors.user_code.0 as u64;
        ctx.ss = selectors.user_data.0 as u64;
        ctx
    }

    fn empty() -> Self {
        Self {
            regs: GeneralRegisters::zero(),
            rip: 0,
            rsp: 0,
            rflags: 0,
            cs: 0,
            ss: 0,
        }
    }

    /// Return the code segment selector.
    pub fn code_segment(&self) -> u64 {
        self.cs
    }

    /// Return the stack segment selector.
    pub fn stack_segment(&self) -> u64 {
        self.ss
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone)]
pub struct AddressSpace {
    inner: Arc<InnerAddressSpace>,
}

impl AddressSpace {
    pub fn current() -> Self {
        Self {
            inner: address_space::kernel_address_space(),
        }
    }

    pub fn from_arc(inner: Arc<InnerAddressSpace>) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &Arc<InnerAddressSpace> {
        &self.inner
    }

    pub unsafe fn activate(&self) {
        unsafe { self.inner.activate() };
    }
}

fn virt_to_u64(addr: VirtAddr) -> u64 {
    u64::try_from(addr.as_raw()).expect("virtual address exceeds architectural width")
}

fn align_down_u64(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    value & !(align - 1)
}

fn align_up_usize(value: usize, align: usize) -> usize {
    debug_assert!(align.is_power_of_two(), "alignment must be power of two");
    (value + align - 1) & !(align - 1)
}

fn rollback_user_mapping(
    table: &mut crate::arch::x86_64::mem::paging::X86PageTable<crate::mem::mapper::OffsetMapper>,
    allocator: &mut crate::mem::frame::FrameAllocatorGuard<'_>,
    mapped_pages: &[VirtAddr],
) {
    for addr in mapped_pages.iter().rev() {
        let page = Page::new(*addr, PageSize::SIZE_4K);
        if let Ok(frame) = table.unmap(page) {
            allocator.deallocate(frame);
        }
    }
}
