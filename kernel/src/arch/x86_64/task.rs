use core::convert::TryFrom;

use x86_64::{
    instructions::segmentation::{CS, SS, Segment},
    registers::control::{Cr3, Cr3Flags},
    structures::paging::PhysFrame,
};

use crate::mem::addr::VirtAddr;

use super::trap::{GeneralRegisters, TrapFrame};

const STACK_ALIGNMENT: u64 = 16;
const RFLAGS_RESERVED: u64 = 1 << 1;
const RFLAGS_INTERRUPT_ENABLE: u64 = 1 << 9;

/// Saved CPU context for a suspended kernel task (thread).
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

        let cs = CS::get_reg();
        let ss = SS::get_reg();
        ctx.cs = cs.0 as u64;
        ctx.ss = ss.0 as u64;
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
}

impl Default for Context {
    fn default() -> Self {
        Self::empty()
    }
}

#[derive(Clone, Copy)]
pub struct AddressSpace {
    frame: PhysFrame,
    flags: Cr3Flags,
}

impl AddressSpace {
    pub fn current() -> Self {
        let (frame, flags) = Cr3::read();
        Self { frame, flags }
    }

    /// # Safety
    ///
    /// Callers must guarantee that the supplied address space keeps the kernel's critical code and
    /// data mapped and that switching CR3 does not invalidate the current stack frame. Typically
    /// interrupts should be disabled around the transition.
    pub unsafe fn activate(space: &Self) {
        unsafe { Cr3::write(space.frame, space.flags) };
    }
}

fn virt_to_u64(addr: VirtAddr) -> u64 {
    u64::try_from(addr.as_raw()).expect("virtual address exceeds architectural width")
}

fn align_down_u64(value: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    value & !(align - 1)
}
