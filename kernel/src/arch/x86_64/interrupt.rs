use core::arch::asm;
use core::convert::TryFrom;
use core::sync::atomic::{AtomicU64, Ordering};

use bootloader_api::BootInfo;

use crate::arch::api::{InterruptInitError, TimerDriver, TimerError, TimerMode, TimerTicks};
use crate::device::bus::reg::RegBus;
use crate::util::spinlock::SpinLock;

use super::bus::Pio;
use x86_64::VirtAddr as X86VirtAddr;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{PageTable, PageTableFlags};

pub const TIMER_VECTOR: u8 = 32;

const IA32_APIC_BASE: u32 = 0x1B;
const APIC_ENABLE: u64 = 1 << 11;
const APIC_BASE_MASK: u64 = 0xffff_f000;

const SPURIOUS_VECTOR: u8 = 0xFF;

const REG_TPR: usize = 0x80;
const REG_EOI: usize = 0xB0;
const REG_SVR: usize = 0xF0;
const REG_LVT_TIMER: usize = 0x320;
const REG_LVT_LINT0: usize = 0x350;
const REG_LVT_LINT1: usize = 0x360;
const REG_LVT_ERROR: usize = 0x370;
const REG_TIMER_INITIAL: usize = 0x380;
const REG_TIMER_DIVIDE: usize = 0x3E0;

const DIVIDE_BY_16: u32 = 0b0011;
const LVT_MASK: u32 = 1 << 16;
const LVT_MODE_PERIODIC: u32 = 0b01 << 17;

pub static LOCAL_APIC: LocalApic = LocalApic::new();
pub static TIMER_DEVICE: LocalApicTimer = LocalApicTimer::new();

pub struct LocalApic {
    base: AtomicU64,
    timer_state: SpinLock<TimerState>,
}

impl LocalApic {
    pub const fn new() -> Self {
        Self {
            base: AtomicU64::new(0),
            timer_state: SpinLock::new(TimerState::new()),
        }
    }

    pub fn init(&'static self, boot_info: &'static BootInfo) -> Result<(), InterruptInitError> {
        if self.base.load(Ordering::Acquire) != 0 {
            return Err(InterruptInitError::AlreadyInitialised);
        }

        let phys_offset = boot_info
            .physical_memory_offset
            .as_ref()
            .copied()
            .ok_or(InterruptInitError::MissingPhysicalMapping)?;

        let mut apic_base = unsafe { rdmsr(IA32_APIC_BASE) };
        if apic_base & APIC_ENABLE == 0 {
            apic_base |= APIC_ENABLE;
            unsafe { wrmsr(IA32_APIC_BASE, apic_base) };
        }

        let base_phys = apic_base & APIC_BASE_MASK;
        let virt_base = base_phys
            .checked_add(phys_offset)
            .ok_or(InterruptInitError::AddressOverflow)?;
        let base_usize =
            usize::try_from(virt_base).map_err(|_| InterruptInitError::AddressOverflow)?;

        self.ensure_lapic_uncacheable(base_usize, phys_offset)?;

        self.base.store(base_usize as u64, Ordering::Release);

        self.mask_8259_pic();

        let regs = unsafe { LocalApicRegs::new(base_usize as *mut u8) };

        unsafe {
            regs.write(REG_TPR, 0);
            regs.write(REG_LVT_LINT0, LVT_MASK);
            regs.write(REG_LVT_LINT1, LVT_MASK);
            regs.write(REG_LVT_ERROR, (SPURIOUS_VECTOR as u32) | LVT_MASK);
            regs.write(REG_LVT_TIMER, (TIMER_VECTOR as u32) | LVT_MASK);
            regs.write(REG_TIMER_DIVIDE, DIVIDE_BY_16);
            regs.write(REG_TIMER_INITIAL, 0);
            regs.write(REG_SVR, (SPURIOUS_VECTOR as u32) | (1 << 8));
        }

        self.timer_state().lock().running = false;

        Ok(())
    }

    pub fn enable(&self) {
        x86_64::instructions::interrupts::enable();
    }

    pub fn disable(&self) {
        x86_64::instructions::interrupts::disable();
    }

    pub fn end_of_interrupt(&self, vector: u8) {
        if vector < 32 {
            return;
        }

        if let Some(regs) = self.regs() {
            unsafe { regs.write(REG_EOI, 0) };
        }
    }

    pub fn timer(&'static self) -> &'static LocalApicTimer {
        &TIMER_DEVICE
    }

    fn regs(&self) -> Option<LocalApicRegs> {
        let base = self.base.load(Ordering::Acquire);
        if base == 0 {
            None
        } else {
            Some(unsafe { LocalApicRegs::new(base as *mut u8) })
        }
    }

    fn timer_state(&self) -> &SpinLock<TimerState> {
        &self.timer_state
    }

    fn mask_8259_pic(&self) {
        const PIC1_BASE: u16 = 0x20;
        const PIC2_BASE: u16 = 0xA0;

        let pic1 = Pio::new(PIC1_BASE);
        let pic2 = Pio::new(PIC2_BASE);

        let _ = pic1.write(1, 0xFF);
        let _ = pic2.write(1, 0xFF);
    }

    /// Ensure the local APIC MMIO range is mapped with UC/WT attributes.
    ///
    /// # Implicit contract
    ///
    /// The implementation assumes a direct physical-memory window located at `phys_offset`
    /// such that `phys + phys_offset` yields the virtual address of the same frame. Boot code must
    /// establish that mapping prior to invoking this routine.
    fn ensure_lapic_uncacheable(
        &self,
        virt_base: usize,
        phys_offset: u64,
    ) -> Result<(), InterruptInitError> {
        let target = X86VirtAddr::new(virt_base as u64);
        let (level_4_frame, _) = Cr3::read();
        let offset = X86VirtAddr::new(phys_offset);
        let mut table_ptr =
            (offset + level_4_frame.start_address().as_u64()).as_u64() as *mut PageTable;
        let indices = [
            usize::from(target.p4_index()),
            usize::from(target.p3_index()),
            usize::from(target.p2_index()),
            usize::from(target.p1_index()),
        ];

        for (level, &idx) in indices.iter().enumerate() {
            let table = unsafe { &mut *table_ptr };
            let entry = &mut table[idx];
            if !entry.flags().contains(PageTableFlags::PRESENT) {
                return Err(InterruptInitError::ApicUnavailable);
            }

            let is_huge = entry.flags().contains(PageTableFlags::HUGE_PAGE);
            let is_leaf = level == indices.len() - 1 || is_huge;

            if is_leaf {
                let mut flags = entry.flags();
                let desired = PageTableFlags::NO_CACHE | PageTableFlags::WRITE_THROUGH;
                if !flags.contains(PageTableFlags::NO_CACHE)
                    || !flags.contains(PageTableFlags::WRITE_THROUGH)
                {
                    flags.insert(desired);
                    entry.set_flags(flags);

                    if is_huge {
                        x86_64::instructions::tlb::flush_all();
                    } else {
                        x86_64::instructions::tlb::flush(target);
                    }
                }
                return Ok(());
            }

            let next_phys = entry.addr().as_u64();
            table_ptr = (offset + next_phys).as_u64() as *mut PageTable;
        }

        Err(InterruptInitError::ApicUnavailable)
    }
}

struct TimerState {
    running: bool,
}

impl TimerState {
    const fn new() -> Self {
        Self { running: false }
    }
}

struct LocalApicRegs {
    base: *mut u8,
}

impl LocalApicRegs {
    unsafe fn new(base: *mut u8) -> Self {
        Self { base }
    }

    unsafe fn write(&self, offset: usize, value: u32) {
        let ptr = unsafe { self.base.add(offset) as *mut u32 };
        unsafe {
            ptr.write_volatile(value);
        }
    }
}

pub struct LocalApicTimer;

impl LocalApicTimer {
    const fn new() -> Self {
        Self
    }

    fn controller(&self) -> &'static LocalApic {
        &LOCAL_APIC
    }
}

impl TimerDriver for LocalApicTimer {
    fn configure(&self, mode: TimerMode, ticks: TimerTicks) -> Result<(), TimerError> {
        if ticks.raw() == 0 {
            return Err(TimerError::InvalidTicks);
        }

        let controller = self.controller();
        let regs = controller.regs().ok_or(TimerError::NotInitialised)?;
        let mut state = controller.timer_state().lock();

        if state.running {
            return Err(TimerError::AlreadyRunning);
        }

        let mut lvt = (TIMER_VECTOR as u32) & 0xFF;
        if matches!(mode, TimerMode::Periodic) {
            lvt |= LVT_MODE_PERIODIC;
        }

        unsafe {
            regs.write(REG_LVT_TIMER, (TIMER_VECTOR as u32) | LVT_MASK);
            regs.write(REG_TIMER_DIVIDE, DIVIDE_BY_16);
            regs.write(REG_TIMER_INITIAL, ticks.raw());
            regs.write(REG_LVT_TIMER, lvt);
        }

        state.running = true;

        Ok(())
    }

    fn stop(&self) -> Result<(), TimerError> {
        let controller = self.controller();
        let regs = controller.regs().ok_or(TimerError::NotInitialised)?;
        let mut state = controller.timer_state().lock();

        if !state.running {
            return Err(TimerError::NotRunning);
        }

        unsafe {
            regs.write(REG_LVT_TIMER, (TIMER_VECTOR as u32) | LVT_MASK);
            regs.write(REG_TIMER_INITIAL, 0);
        }

        state.running = false;

        Ok(())
    }
}

unsafe fn rdmsr(msr: u32) -> u64 {
    let high: u32;
    let low: u32;
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("edx") high, out("eax") low, options(nostack, preserves_flags));
    }
    ((high as u64) << 32) | (low as u64)
}

unsafe fn wrmsr(msr: u32, value: u64) {
    let high = (value >> 32) as u32;
    let low = value as u32;
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("edx") high, in("eax") low, options(nostack, preserves_flags));
    }
}
