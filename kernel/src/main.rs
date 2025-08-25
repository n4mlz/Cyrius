#![no_std]
#![no_main]

use bootloader_api::{entry_point, BootInfo};
use core::panic::PanicInfo;

entry_point!(kernel_main);

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags));
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let mut v: u8;
    core::arch::asm!("in al, dx", in("dx") port, out("al") v, options(nostack, preserves_flags));
    v
}

const COM1: u16 = 0x3F8;

unsafe fn serial_init() {
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1 + 0, 0x03);
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
}

unsafe fn serial_can_tx() -> bool {
    (inb(COM1 + 5) & 0x20) != 0
}

unsafe fn serial_putc(c: u8) {
    while !serial_can_tx() {}
    outb(COM1, c);
}

fn puts(s: &str) {
    unsafe {
        for b in s.bytes() {
            if b == b'\n' {
                serial_putc(b'\r');
            }
            serial_putc(b);
        }
    }
}

fn kernel_main(_boot_info: &'static mut BootInfo) -> ! {
    unsafe {
        serial_init();
    }
    puts("hello, world!\n");
    loop {
        core::hint::spin_loop()
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    puts("panic!\n");
    loop {
        core::hint::spin_loop()
    }
}
