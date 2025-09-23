use core::arch::{asm, naked_asm};
use core::hint::spin_loop;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::api::{
    ArchTrapController, TrapFrame, TrapHandler, TrapInfo, TrapKind, TrapOrigin,
};
use crate::mem::addr::{Addr, VirtAddr};
use crate::util::spinlock::SpinLock;
use crate::{print, println};

pub struct X86TrapController {
    handler: SpinLock<Option<&'static dyn TrapHandler<Frame = X86TrapFrame>>>,
    idt_loaded: AtomicBool,
}

impl X86TrapController {
    pub const fn new() -> Self {
        Self {
            handler: SpinLock::new(None),
            idt_loaded: AtomicBool::new(false),
        }
    }

    pub fn instance() -> &'static Self {
        &CONTROLLER
    }

    fn dispatch(&self, frame_ptr: *mut X86TrapFrame, vector: u8) {
        let handler = {
            let guard = self.handler.lock();
            *guard
        };

        let handler = handler.unwrap_or_else(|| {
            println!("no trap handler installed (vector={})", vector);
            loop {
                spin_loop();
            }
        });

        let frame = unsafe { &mut *frame_ptr };
        if (frame.cs & 0x3) == 0 {
            frame.rsp = 0;
            frame.ss = 0;
        }

        let info = describe_trap(vector, frame);
        handler.handle_trap(frame, info);
    }
}

impl ArchTrapController for X86TrapController {
    type Frame = X86TrapFrame;

    fn init(&self, handler: &'static dyn TrapHandler<Frame = Self::Frame>) {
        {
            let mut guard = self.handler.lock();
            *guard = Some(handler);
        }

        if self
            .idt_loaded
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            unsafe { init_idt() };
        }
    }
}

pub fn controller() -> &'static X86TrapController {
    X86TrapController::instance()
}

#[repr(C)]
#[derive(Debug)]
pub struct X86TrapFrame {
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl TrapFrame for X86TrapFrame {}

static CONTROLLER: X86TrapController = X86TrapController::new();

#[repr(C, align(16))]
struct Idt {
    entries: [IdtEntry; 256],
}

impl Idt {
    const fn new() -> Self {
        Self {
            entries: [IdtEntry::missing(); 256],
        }
    }

    fn set_handler(&mut self, index: usize, selector: u16, handler: Handler) {
        self.entries[index].set_handler(selector, handler);
    }
}

#[repr(C, packed)]
#[derive(Copy, Clone)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    attributes: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            attributes: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    fn set_handler(&mut self, selector: u16, handler: Handler) {
        let addr = handler as usize as u64;
        self.offset_low = addr as u16;
        self.selector = selector;
        self.ist = 0;
        self.attributes = 0x8E; // present, DPL0, interrupt gate
        self.offset_mid = ((addr >> 16) & 0xffff) as u16;
        self.offset_high = ((addr >> 32) & 0xffff_ffff) as u32;
        self.reserved = 0;
    }
}

type Handler = unsafe extern "C" fn();

#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

impl DescriptorTablePointer {
    fn new(idt: &Idt) -> Self {
        Self {
            limit: (core::mem::size_of::<Idt>() - 1) as u16,
            base: idt as *const _ as u64,
        }
    }
}

unsafe fn lidt(ptr: &DescriptorTablePointer) {
    unsafe {
        asm!("lidt [{ptr}]", ptr = in(reg) ptr, options(nostack, readonly));
    }
}

static mut IDT: Idt = Idt::new();

unsafe fn init_idt() {
    let cs: u16;
    unsafe {
        asm!("mov {0:x}, cs", out(reg) cs, options(nomem, preserves_flags));
    }

    let idt_ptr = core::ptr::addr_of_mut!(IDT);
    for (index, handler) in EXCEPTION_HANDLERS.iter().enumerate() {
        unsafe {
            (*idt_ptr).set_handler(index, cs, *handler);
        }
    }

    let ptr = DescriptorTablePointer::new(unsafe { &*idt_ptr });
    unsafe {
        lidt(&ptr);
    }
}

macro_rules! trap_stub {
    ($name:ident, $vector:expr, true) => {
        trap_stub!(@impl $name, $vector);
    };
    ($name:ident, $vector:expr, false) => {
        trap_stub!(@impl $name, $vector, "push 0");
    };
    (@impl $name:ident, $vector:expr $(, $prefix:literal)?) => {
        #[unsafe(naked)]
        unsafe extern "C" fn $name() {
            naked_asm!(
                $($prefix,)?
                "push r15",
                "push r14",
                "push r13",
                "push r12",
                "push r11",
                "push r10",
                "push r9",
                "push r8",
                "push rdi",
                "push rsi",
                "push rbp",
                "push rbx",
                "push rdx",
                "push rcx",
                "push rax",
                "mov rdi, rsp",
                "mov esi, {vector}",
                "call {dispatch}",
                "pop rax",
                "pop rcx",
                "pop rdx",
                "pop rbx",
                "pop rbp",
                "pop rsi",
                "pop rdi",
                "pop r8",
                "pop r9",
                "pop r10",
                "pop r11",
                "pop r12",
                "pop r13",
                "pop r14",
                "pop r15",
                "add rsp, 8",
                "iretq",
                dispatch = sym trap_dispatch,
                vector = const $vector
            );
        }
    };
}

trap_stub!(trap_divide_error, 0, false);
trap_stub!(trap_debug, 1, false);
trap_stub!(trap_non_maskable, 2, false);
trap_stub!(trap_breakpoint, 3, false);
trap_stub!(trap_overflow, 4, false);
trap_stub!(trap_bound_range, 5, false);
trap_stub!(trap_invalid_opcode, 6, false);
trap_stub!(trap_device_not_available, 7, false);
trap_stub!(trap_double_fault, 8, true);
trap_stub!(trap_coprocessor_segment, 9, false);
trap_stub!(trap_invalid_tss, 10, true);
trap_stub!(trap_segment_not_present, 11, true);
trap_stub!(trap_stack_segment, 12, true);
trap_stub!(trap_general_protection, 13, true);
trap_stub!(trap_page_fault, 14, true);
trap_stub!(trap_reserved_15, 15, false);
trap_stub!(trap_x87, 16, false);
trap_stub!(trap_alignment_check, 17, true);
trap_stub!(trap_machine_check, 18, false);
trap_stub!(trap_simd, 19, false);
trap_stub!(trap_virtualization, 20, false);
trap_stub!(trap_control_protection, 21, true);
trap_stub!(trap_reserved_22, 22, false);
trap_stub!(trap_reserved_23, 23, false);
trap_stub!(trap_reserved_24, 24, false);
trap_stub!(trap_reserved_25, 25, false);
trap_stub!(trap_reserved_26, 26, false);
trap_stub!(trap_reserved_27, 27, false);
trap_stub!(trap_hypervisor, 28, false);
trap_stub!(trap_vmm_communication, 29, true);
trap_stub!(trap_security, 30, true);
trap_stub!(trap_reserved_31, 31, false);

const EXCEPTION_HANDLERS: [Handler; 32] = [
    trap_divide_error,
    trap_debug,
    trap_non_maskable,
    trap_breakpoint,
    trap_overflow,
    trap_bound_range,
    trap_invalid_opcode,
    trap_device_not_available,
    trap_double_fault,
    trap_coprocessor_segment,
    trap_invalid_tss,
    trap_segment_not_present,
    trap_stack_segment,
    trap_general_protection,
    trap_page_fault,
    trap_reserved_15,
    trap_x87,
    trap_alignment_check,
    trap_machine_check,
    trap_simd,
    trap_virtualization,
    trap_control_protection,
    trap_reserved_22,
    trap_reserved_23,
    trap_reserved_24,
    trap_reserved_25,
    trap_reserved_26,
    trap_reserved_27,
    trap_hypervisor,
    trap_vmm_communication,
    trap_security,
    trap_reserved_31,
];

unsafe extern "C" fn trap_dispatch(frame_ptr: *mut X86TrapFrame, vector: u64) {
    controller().dispatch(frame_ptr, vector as u8);
}

fn describe_trap(vector: u8, frame: &X86TrapFrame) -> TrapInfo {
    let (origin, kind, description) = match vector {
        0 => (TrapOrigin::Exception, TrapKind::Fault, "Divide Error"),
        1 => (TrapOrigin::Exception, TrapKind::Debug, "Debug"),
        2 => (
            TrapOrigin::Nmi,
            TrapKind::Interrupt,
            "Non-Maskable Interrupt",
        ),
        3 => (TrapOrigin::Exception, TrapKind::Debug, "Breakpoint"),
        4 => (TrapOrigin::Exception, TrapKind::Debug, "Overflow"),
        5 => (
            TrapOrigin::Exception,
            TrapKind::Fault,
            "Bound Range Exceeded",
        ),
        6 => (TrapOrigin::Exception, TrapKind::Fault, "Invalid Opcode"),
        7 => (
            TrapOrigin::Exception,
            TrapKind::Fault,
            "Device Not Available",
        ),
        8 => (TrapOrigin::Exception, TrapKind::Abort, "Double Fault"),
        9 => (
            TrapOrigin::Exception,
            TrapKind::Fault,
            "Coprocessor Segment Overrun",
        ),
        10 => (TrapOrigin::Exception, TrapKind::Fault, "Invalid TSS"),
        11 => (
            TrapOrigin::Exception,
            TrapKind::Fault,
            "Segment Not Present",
        ),
        12 => (
            TrapOrigin::Exception,
            TrapKind::Fault,
            "Stack-Segment Fault",
        ),
        13 => (
            TrapOrigin::Exception,
            TrapKind::Fault,
            "General Protection Fault",
        ),
        14 => (TrapOrigin::Exception, TrapKind::Fault, "Page Fault"),
        15 => (TrapOrigin::Exception, TrapKind::Other, "Reserved"),
        16 => (TrapOrigin::Exception, TrapKind::Fault, "x87 Floating Point"),
        17 => (TrapOrigin::Exception, TrapKind::Fault, "Alignment Check"),
        18 => (TrapOrigin::Exception, TrapKind::Abort, "Machine Check"),
        19 => (
            TrapOrigin::Exception,
            TrapKind::Fault,
            "SIMD Floating Point",
        ),
        20 => (TrapOrigin::Exception, TrapKind::Fault, "Virtualization"),
        21 => (TrapOrigin::Exception, TrapKind::Fault, "Control Protection"),
        22 => (TrapOrigin::Exception, TrapKind::Other, "Reserved"),
        23 => (TrapOrigin::Exception, TrapKind::Other, "Reserved"),
        24 => (TrapOrigin::Exception, TrapKind::Other, "Reserved"),
        25 => (TrapOrigin::Exception, TrapKind::Other, "Reserved"),
        26 => (TrapOrigin::Exception, TrapKind::Other, "Reserved"),
        27 => (TrapOrigin::Exception, TrapKind::Other, "Reserved"),
        28 => (
            TrapOrigin::Exception,
            TrapKind::Fault,
            "Hypervisor Injection",
        ),
        29 => (TrapOrigin::Exception, TrapKind::Fault, "VMM Communication"),
        30 => (TrapOrigin::Exception, TrapKind::Abort, "Security Exception"),
        31 => (TrapOrigin::Exception, TrapKind::Other, "Reserved"),
        _ => (TrapOrigin::Unknown, TrapKind::Other, "Unknown"),
    };

    let error_code = if has_error_code(vector) {
        Some(frame.error_code)
    } else {
        None
    };

    let fault_address = if vector == 14 { Some(read_cr2()) } else { None };

    TrapInfo::new(
        vector as u16,
        origin,
        kind,
        description,
        error_code,
        fault_address,
    )
}

fn has_error_code(vector: u8) -> bool {
    matches!(vector, 8 | 10 | 11 | 12 | 13 | 14 | 17 | 21 | 29 | 30)
}

fn read_cr2() -> VirtAddr {
    let addr: u64;
    unsafe {
        asm!("mov {0}, cr2", out(reg) addr, options(nomem, preserves_flags));
    }
    VirtAddr::from_usize(addr as usize)
}
