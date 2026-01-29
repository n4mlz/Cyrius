pub mod bus;
pub mod interrupt;
pub mod loader;
pub mod mem;
pub mod pci;
pub mod syscall;
mod thread;
mod trap;
mod xsave;

pub use thread::AddressSpace;
pub use trap::{GeneralRegisters, SYSCALL_VECTOR, TrapFrame};

use self::trap::gdt;

use bootloader_api::BootInfo;
use core::arch::asm;

use crate::arch::api::{
    ArchDevice, ArchInterrupt, ArchMemory, ArchPlatform, ArchThread, ArchTrap, HeapRegionError,
    InterruptInitError, MsiMessage, UserAddressSpaceError, UserStackError,
};
use crate::device::char::uart::ns16550::Ns16550;
use crate::mem::addr::{AddrRange, VirtAddr};

use self::bus::Pio;

pub struct X86_64;

impl From<mem::address_space::AddressSpaceError> for UserAddressSpaceError {
    fn from(err: mem::address_space::AddressSpaceError) -> Self {
        match err {
            mem::address_space::AddressSpaceError::FrameAllocationFailed => {
                UserAddressSpaceError::FrameAllocationFailed
            }
            mem::address_space::AddressSpaceError::MapFailed(err) => {
                UserAddressSpaceError::MapFailed(err)
            }
            mem::address_space::AddressSpaceError::UnsupportedMapping => {
                UserAddressSpaceError::UnsupportedMapping
            }
        }
    }
}

/// Enable FPU/SSE for user code by configuring CR0/CR4. This is a coarse initialisation and does
/// not yet save/restore FPU state per thread.
pub fn init_cpu_features() {
    xsave::enable_sse();
}

const IA32_FS_BASE: u32 = 0xC000_0100;

pub fn set_fs_base(value: u64) {
    unsafe { wrmsr(IA32_FS_BASE, value) };
}

impl ArchPlatform for X86_64 {
    fn name() -> &'static str {
        "x86_64"
    }
}

impl ArchDevice for X86_64 {
    type Console = Ns16550<u8, Pio>;

    fn console() -> &'static Self::Console {
        static UART0: Ns16550<u8, Pio> = Ns16550::new(Pio::new(0x3F8), "kernel-console");
        &UART0
    }
}

impl ArchTrap for X86_64 {
    type Frame = trap::TrapFrame;

    fn init_traps() {
        trap::init();
    }

    fn dispatch_trap(info: crate::trap::TrapInfo, frame: &mut Self::Frame) {
        crate::trap::dispatch(info, frame);
    }

    fn handle_exception(info: crate::trap::TrapInfo, frame: &mut Self::Frame) -> bool {
        trap::handle_exception(info, frame)
    }
}

impl ArchMemory for X86_64 {
    fn locate_kernel_heap(
        boot_info: &'static BootInfo,
    ) -> Result<AddrRange<VirtAddr>, HeapRegionError> {
        self::mem::locate_kernel_heap(boot_info)
    }
}

pub fn halt() {
    x86_64::instructions::hlt();
}

impl ArchInterrupt for X86_64 {
    type Timer = interrupt::LocalApicTimer;

    fn init_interrupts(boot_info: &'static BootInfo) -> Result<(), InterruptInitError> {
        interrupt::LOCAL_APIC.init(boot_info)
    }

    fn are_interrupts_enabled() -> bool {
        x86_64::instructions::interrupts::are_enabled()
    }

    fn enable_interrupts() {
        interrupt::LOCAL_APIC.enable();
    }

    fn disable_interrupts() {
        interrupt::LOCAL_APIC.disable();
    }

    fn end_of_interrupt(vector: u8) {
        interrupt::LOCAL_APIC.end_of_interrupt(vector);
    }

    fn timer() -> &'static Self::Timer {
        interrupt::LOCAL_APIC.timer()
    }

    fn timer_vector() -> u8 {
        interrupt::TIMER_VECTOR
    }

    fn msi_message(vector: u8) -> Option<MsiMessage> {
        interrupt::LOCAL_APIC.msi_message(vector)
    }
}

impl ArchThread for X86_64 {
    type Context = thread::Context;
    type AddressSpace = thread::AddressSpace;
    type UserStack = thread::UserStack;

    fn save_context(frame: &crate::trap::CurrentTrapFrame) -> Self::Context {
        thread::Context::from_trap(frame)
    }

    unsafe fn restore_context(frame: &mut crate::trap::CurrentTrapFrame, ctx: &Self::Context) {
        thread::Context::write_to_trap(ctx, frame);
    }

    fn bootstrap_kernel_context(entry: VirtAddr, stack_top: VirtAddr) -> Self::Context {
        thread::Context::for_kernel(entry, stack_top)
    }

    fn bootstrap_user_context(entry: VirtAddr, stack_top: VirtAddr) -> Self::Context {
        thread::Context::for_user(entry, stack_top)
    }

    fn bootstrap_user_context_with_stack_pointer(
        entry: VirtAddr,
        stack_pointer: VirtAddr,
    ) -> Self::Context {
        thread::Context::for_user_with_stack_pointer(entry, stack_pointer)
    }

    fn current_address_space() -> Self::AddressSpace {
        thread::AddressSpace::current()
    }

    unsafe fn activate_address_space(space: &Self::AddressSpace) {
        unsafe {
            space.activate();
        }
    }

    fn allocate_user_stack(
        space: &Self::AddressSpace,
        size: usize,
    ) -> Result<Self::UserStack, UserStackError> {
        thread::UserStack::allocate(space, size)
    }

    fn user_stack_top(stack: &Self::UserStack) -> VirtAddr {
        stack.top()
    }

    fn user_stack_base(stack: &Self::UserStack) -> VirtAddr {
        stack.base()
    }

    fn user_stack_size(stack: &Self::UserStack) -> usize {
        stack.size()
    }

    fn user_stack_from_existing(
        space: &Self::AddressSpace,
        base: VirtAddr,
        size: usize,
    ) -> Result<Self::UserStack, UserStackError> {
        thread::UserStack::from_existing(space, base, size)
    }

    fn set_syscall_return(ctx: &mut Self::Context, value: u64) {
        ctx.set_syscall_return(value);
    }

    fn set_stack_pointer(ctx: &mut Self::Context, stack_pointer: VirtAddr) {
        ctx.set_stack_pointer(stack_pointer);
    }

    fn update_privilege_stack(stack_top: VirtAddr) {
        gdt::set_privilege_stack(stack_top);
    }

    fn create_user_address_space() -> Result<Self::AddressSpace, UserAddressSpaceError> {
        let inner = mem::address_space::create_user_space().map_err(UserAddressSpaceError::from)?;
        Ok(thread::AddressSpace::from_arc(inner))
    }

    fn clone_user_address_space(
        source: &Self::AddressSpace,
    ) -> Result<Self::AddressSpace, UserAddressSpaceError> {
        let inner = mem::address_space::clone_user_space(source.inner())
            .map_err(UserAddressSpaceError::from)?;
        Ok(thread::AddressSpace::from_arc(inner))
    }

    fn clear_user_mappings(space: &Self::AddressSpace) -> Result<(), UserAddressSpaceError> {
        mem::address_space::clear_user_mappings(space.inner()).map_err(UserAddressSpaceError::from)
    }
}

impl crate::arch::api::ArchPlatformHooks for X86_64 {
    type LinuxElfPlatform = loader::X86LinuxElfPlatform;
}

unsafe fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("edx") high,
            in("eax") low,
            options(nostack, preserves_flags)
        );
    }
}
