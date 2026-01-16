use alloc::{sync::Arc, vec::Vec};
use core::convert::TryFrom;

use crate::arch::x86_64::mem::address_space::{self, AddressSpace as InnerAddressSpace};
use crate::mem::addr::{Addr, MemPerm, Page, PageSize, VirtAddr, VirtIntoPtr, align_down_u64};
use crate::mem::paging::{FrameAllocator, PageTableOps, UnmapError};

use super::trap::{GeneralRegisters, TrapFrame, gdt};

const STACK_ALIGNMENT: u64 = 16;
const RFLAGS_RESERVED: u64 = 1 << 1;
const RFLAGS_INTERRUPT_ENABLE: u64 = 1 << 9;
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
        let (base, aligned) = space.inner().allocate_user_stack_region(size)?;

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
            space.inner().deallocate_user_stack_region(base, aligned);
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

        self.space
            .inner()
            .deallocate_user_stack_region(self.base.as_raw(), self.size);
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

    pub fn for_user_with_stack_pointer(entry: VirtAddr, stack_pointer: VirtAddr) -> Self {
        let mut ctx = Self::empty();
        ctx.rip = virt_to_u64(entry);
        ctx.rsp = virt_to_u64(stack_pointer);
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

    /// # Safety
    ///
    /// Caller must ensure the provided address space remains valid and mapped
    /// for the duration of execution, and that switching CR3 here does not
    /// race with concurrent mutations of the same tables.
    pub unsafe fn activate(&self) {
        unsafe { self.inner.activate() };
    }

    pub fn with_table<F, R>(&self, f: F) -> R
    where
        F: FnMut(
            &mut crate::arch::x86_64::mem::paging::X86PageTable<crate::mem::mapper::OffsetMapper>,
            &mut crate::mem::frame::FrameAllocatorGuard<'_>,
        ) -> R,
    {
        self.inner.with_table(f)
    }
}

fn virt_to_u64(addr: VirtAddr) -> u64 {
    u64::try_from(addr.as_raw()).expect("virtual address exceeds architectural width")
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
