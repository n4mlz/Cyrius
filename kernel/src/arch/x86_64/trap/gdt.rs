use x86_64::{
    PrivilegeLevel, VirtAddr,
    instructions::tables::load_tss,
    registers::segmentation::{CS, SS, Segment},
    structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector},
    structures::tss::TaskStateSegment,
};

use crate::mem::addr::VirtAddr as KernelVirtAddr;
use crate::util::{lazylock::LazyLock, spinlock::SpinLock};

pub(super) const IST_INDEX_NMI: u16 = 1;
pub(super) const IST_INDEX_DOUBLE_FAULT: u16 = 2;
pub(super) const IST_INDEX_MACHINE_CHECK: u16 = 3;

const IST_STACK_SIZE: usize = 32 * 1024;
const IST_STACK_COUNT: usize = 3;
const PRIVILEGE_STACK_SIZE: usize = 32 * 1024;

#[repr(align(16))]
struct IstStackArea([u8; IST_STACK_SIZE * IST_STACK_COUNT]);

static mut IST_STACKS: IstStackArea = IstStackArea([0u8; IST_STACK_SIZE * IST_STACK_COUNT]);

#[repr(align(16))]
struct PrivilegeStack([u8; PRIVILEGE_STACK_SIZE]);

static mut PRIV_STACK: PrivilegeStack = PrivilegeStack([0u8; PRIVILEGE_STACK_SIZE]);

pub(crate) struct GdtSelectors {
    pub(crate) kernel_code: SegmentSelector,
    pub(crate) kernel_data: SegmentSelector,
    pub(crate) user_code: SegmentSelector,
    pub(crate) user_data: SegmentSelector,
    pub(crate) tss: SegmentSelector,
}

type GdtInit = (GlobalDescriptorTable, GdtSelectors);
type GdtBuilder = fn() -> GdtInit;

type TssBuilder = fn() -> SpinLock<TaskStateSegment>;

static TSS: LazyLock<SpinLock<TaskStateSegment>, TssBuilder> = LazyLock::new_const(build_tss);
static GDT: LazyLock<GdtInit, GdtBuilder> = LazyLock::new_const(build_gdt);

/// Loads the architecture GDT/TSS pair required for privileged trap handling.
///
/// # Implicit contract
///
/// Must be called on each CPU before enabling interrupts so that IST stacks and
/// privilege transitions reference valid descriptors.
pub(super) fn load() {
    let (gdt, selectors) = &*GDT;
    gdt.load();

    unsafe {
        CS::set_reg(selectors.kernel_code);
        SS::set_reg(selectors.kernel_data);
        load_tss(selectors.tss);
    }
}

pub(crate) fn selectors() -> &'static GdtSelectors {
    let (_, selectors) = &*GDT;
    selectors
}

pub(crate) fn set_privilege_stack(stack_top: KernelVirtAddr) {
    let mut tss = TSS.lock();
    let top = VirtAddr::new(stack_top.as_raw() as u64);
    tss.privilege_stack_table[0] = top;
}

fn build_tss() -> SpinLock<TaskStateSegment> {
    let mut tss = TaskStateSegment::new();
    let stacks_ptr = unsafe { core::ptr::addr_of!(IST_STACKS.0) } as *const u8;
    let base = VirtAddr::new(stacks_ptr as u64);

    tss.interrupt_stack_table[IST_INDEX_NMI as usize - 1] = base + IST_STACK_SIZE as u64;
    tss.interrupt_stack_table[IST_INDEX_DOUBLE_FAULT as usize - 1] =
        base + (IST_STACK_SIZE * 2) as u64;
    tss.interrupt_stack_table[IST_INDEX_MACHINE_CHECK as usize - 1] =
        base + (IST_STACK_SIZE * 3) as u64;

    let priv_stack_ptr = unsafe { core::ptr::addr_of!(PRIV_STACK.0) } as *const u8;
    let priv_top = VirtAddr::new(priv_stack_ptr as u64 + PRIVILEGE_STACK_SIZE as u64);
    tss.privilege_stack_table[0] = priv_top;

    SpinLock::new(tss)
}

fn build_gdt() -> (GlobalDescriptorTable, GdtSelectors) {
    let mut gdt = GlobalDescriptorTable::new();
    let tss_ptr: *const TaskStateSegment = {
        let guard = TSS.lock();
        &*guard as *const TaskStateSegment
    };

    let mut kernel_code = gdt.append(Descriptor::kernel_code_segment());
    let mut kernel_data = gdt.append(Descriptor::kernel_data_segment());
    let mut user_code = gdt.append(Descriptor::user_code_segment());
    let mut user_data = gdt.append(Descriptor::user_data_segment());
    user_code.set_rpl(PrivilegeLevel::Ring3);
    user_data.set_rpl(PrivilegeLevel::Ring3);

    // Ensure kernel selectors have CPL 0 explicitly set for clarity.
    kernel_code.set_rpl(PrivilegeLevel::Ring0);
    kernel_data.set_rpl(PrivilegeLevel::Ring0);

    let tss_sel = gdt.append(Descriptor::tss_segment(unsafe { &*tss_ptr }));

    (
        gdt,
        GdtSelectors {
            kernel_code,
            kernel_data,
            user_code,
            user_data,
            tss: tss_sel,
        },
    )
}
