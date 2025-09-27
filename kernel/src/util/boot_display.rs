use core::fmt::Debug;

use crate::arch::{Arch, api::ArchPlatform};
use crate::boot::{BootInfo, FirmwareRegion, PhysicalRegion, PhysicalRegionKind};
use crate::mem::addr::Addr;
use crate::{print, println};

const LOGO_LINES: [&str; 6] = [
    r"_________               .__              ",
    r"\_   ___ \___.__._______|__|__ __  ______",
    r"/    \  \<   |  |\_  __ \  |  |  \/  ___/",
    r"\     \___\___  | |  | \/  |  |  /\___ \ ",
    r" \______  / ____| |__|  |__|____//____  >",
    r"        \/\/                          \/ ",
];

const FRAME_DELAY_ITERS: usize = 120_000;
const SATURATION: f32 = 0.85;
const VALUE: f32 = 1.0;
const LINE_FACTOR: f32 = 0.045;
const COLUMN_FACTOR: f32 = 0.01;
const FRAME_FACTOR: f32 = 0.05;
const BOOT_INFO_OFFSET: usize = LOGO_LINES.len() + 3;

pub fn run_boot_display(boot_info: &BootInfo<<Arch as ArchPlatform>::ArchBootInfo>) -> !
where
    <Arch as ArchPlatform>::ArchBootInfo: Debug,
{
    print!("\x1b[2J\x1b[H\x1b[?25l");
    render_logo_frame(0);
    print!("\x1b[0m");
    print!("\x1b[{};1H", BOOT_INFO_OFFSET);
    display_boot_info(boot_info);

    let mut frame = 1usize;
    loop {
        render_logo_frame(frame);
        frame = frame.wrapping_add(1);
        frame_delay();
    }
}

fn render_logo_frame(frame: usize) {
    let phase = frame as f32 * FRAME_FACTOR;

    for (row, line) in LOGO_LINES.iter().enumerate() {
        print!("\x1b[{};1H\x1b[2K", row + 1);
        draw_logo_line(row, line, phase);
    }

    print!("\x1b[0m");
    print!("\x1b[{};1H", BOOT_INFO_OFFSET);
}

fn draw_logo_line(row: usize, line: &str, phase: f32) {
    for (column, ch) in line.chars().enumerate() {
        if ch == ' ' {
            print!(" ");
            continue;
        }

        let hue = (row as f32 * LINE_FACTOR) + (column as f32 * COLUMN_FACTOR) + phase;
        let (r, g, b) = hsv_to_rgb(hue);
        print!("\x1b[38;2;{};{};{}m{}", r, g, b, ch);
    }
}

fn display_boot_info<A>(boot_info: &BootInfo<A>)
where
    A: Debug,
{
    println!("== Boot Info (Common) ==");
    println!("  Boot CPU ID        : {}", boot_info.boot_cpu.0);

    let physical = &boot_info.kernel_image.physical;
    println!(
        "  Kernel Image Phys  : {:#018x} - {:#018x}",
        physical.start.as_usize(),
        physical.end.as_usize()
    );
    println!("  Kernel Image Bytes : {}", physical.len());
    println!(
        "  Kernel Virt Offset : {:#018x}",
        boot_info.kernel_image.virtual_offset
    );

    let regions = boot_info.memory_map.regions();
    println!("  Memory Regions ({} total):", regions.len());
    for (index, region) in boot_info.memory_map.iter().enumerate() {
        print_region(index, region);
    }

    println!("\n== Boot Info ({}) ==", Arch::name());
    println!("{:#?}", boot_info.arch_data);
}

fn print_region(index: usize, region: &PhysicalRegion) {
    let start = region.range.start.as_usize();
    let end = region.range.end.as_usize();
    let size = end.saturating_sub(start);

    match region.kind {
        PhysicalRegionKind::Firmware(FirmwareRegion::Uefi(tag)) => {
            println!(
                "    [{:02}] {:#018x} - {:#018x} ({} bytes) Firmware(Uefi:{:#x})",
                index, start, end, size, tag
            );
        }
        PhysicalRegionKind::Firmware(FirmwareRegion::Bios(tag)) => {
            println!(
                "    [{:02}] {:#018x} - {:#018x} ({} bytes) Firmware(Bios:{:#x})",
                index, start, end, size, tag
            );
        }
        PhysicalRegionKind::Usable => {
            println!(
                "    [{:02}] {:#018x} - {:#018x} ({} bytes) Usable",
                index, start, end, size
            );
        }
        PhysicalRegionKind::Bootloader => {
            println!(
                "    [{:02}] {:#018x} - {:#018x} ({} bytes) Bootloader",
                index, start, end, size
            );
        }
        PhysicalRegionKind::Unknown => {
            println!(
                "    [{:02}] {:#018x} - {:#018x} ({} bytes) Unknown",
                index, start, end, size
            );
        }
    }
}

fn hsv_to_rgb(hue: f32) -> (u8, u8, u8) {
    let mut h = hue;
    while h >= 1.0 {
        h -= 1.0;
    }
    while h < 0.0 {
        h += 1.0;
    }

    let scaled = h * 6.0;
    let sector = scaled as i32;
    let frac = scaled - sector as f32;

    let p = VALUE * (1.0 - SATURATION);
    let q = VALUE * (1.0 - SATURATION * frac);
    let t = VALUE * (1.0 - SATURATION * (1.0 - frac));

    let (r, g, b) = match sector % 6 {
        0 => (VALUE, t, p),
        1 => (q, VALUE, p),
        2 => (p, VALUE, t),
        3 => (p, q, VALUE),
        4 => (t, p, VALUE),
        _ => (VALUE, p, q),
    };

    ((r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8)
}

fn frame_delay() {
    for _ in 0..FRAME_DELAY_ITERS {
        core::hint::spin_loop();
    }
}
