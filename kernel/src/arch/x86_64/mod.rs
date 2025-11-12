pub mod bus;
pub mod interrupt;
pub mod mem;
mod thread;
mod trap;

use self::trap::gdt;

use bootloader_api::BootInfo;

use crate::arch::api::{
    ArchDevice, ArchInterrupt, ArchMemory, ArchPlatform, ArchSyscall, ArchThread, ArchTrap,
    HeapRegionError, InterruptInitError, UserImageError, UserStackError,
};
use crate::device::char::uart::ns16550::Ns16550;
use crate::mem::addr::{AddrRange, VirtAddr};

use self::bus::Pio;

pub struct X86_64;

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

    fn handle_exception(info: crate::trap::TrapInfo, frame: &mut Self::Frame) -> bool {
        trap::handle_exception(info, frame)
    }
}

impl ArchSyscall for X86_64 {
    fn syscall_number(frame: &trap::TrapFrame) -> u64 {
        frame.regs.rax
    }

    fn syscall_arg(frame: &trap::TrapFrame, index: usize) -> u64 {
        match index {
            0 => frame.regs.rdi,
            1 => frame.regs.rsi,
            2 => frame.regs.rdx,
            3 => frame.regs.r10,
            4 => frame.regs.r8,
            5 => frame.regs.r9,
            _ => 0,
        }
    }

    fn set_syscall_ret(frame: &mut trap::TrapFrame, value: u64) {
        frame.regs.rax = value;
    }
}

impl ArchMemory for X86_64 {
    fn locate_kernel_heap(
        boot_info: &'static BootInfo,
    ) -> Result<AddrRange<VirtAddr>, HeapRegionError> {
        self::mem::locate_kernel_heap(boot_info)
    }
}

impl ArchInterrupt for X86_64 {
    type Timer = interrupt::LocalApicTimer;

    fn init_interrupts(boot_info: &'static BootInfo) -> Result<(), InterruptInitError> {
        interrupt::LOCAL_APIC.init(boot_info)
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

    fn syscall_vector() -> u8 {
        trap::SYSCALL_VECTOR
    }
}

impl ArchThread for X86_64 {
    type Context = thread::Context;
    type AddressSpace = thread::AddressSpace;
    type UserStack = thread::UserStack;
    type UserImage = thread::UserImage;

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

    fn update_privilege_stack(stack_top: VirtAddr) {
        gdt::set_privilege_stack(stack_top);
    }

    fn map_user_image(
        space: &Self::AddressSpace,
        base: VirtAddr,
        payload: &[u8],
        perms: crate::mem::addr::MemPerm,
    ) -> Result<Self::UserImage, UserImageError> {
        thread::UserImage::map(space, base, payload, perms)
    }

    fn user_image_entry(image: &Self::UserImage) -> VirtAddr {
        image.entry()
    }
}
