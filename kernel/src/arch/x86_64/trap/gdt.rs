use x86_64::{
    VirtAddr,
    instructions::tables::load_tss,
    registers::segmentation::{CS, Segment},
    structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector},
    structures::tss::TaskStateSegment,
};

use crate::util::lazylock::LazyLock;

pub(super) const IST_INDEX_NMI: u16 = 1;
pub(super) const IST_INDEX_DOUBLE_FAULT: u16 = 2;
pub(super) const IST_INDEX_MACHINE_CHECK: u16 = 3;

const IST_STACK_SIZE: usize = 32 * 1024;
const IST_STACK_COUNT: usize = 3;

#[repr(align(16))]
struct IstStackArea([u8; IST_STACK_SIZE * IST_STACK_COUNT]);

static mut IST_STACKS: IstStackArea = IstStackArea([0u8; IST_STACK_SIZE * IST_STACK_COUNT]);

struct GdtSelectors {
    code: SegmentSelector,
    _data: SegmentSelector,
    tss: SegmentSelector,
}

type GdtInit = (GlobalDescriptorTable, GdtSelectors);
type GdtBuilder = fn() -> GdtInit;

static TSS: LazyLock<TaskStateSegment, fn() -> TaskStateSegment> = LazyLock::new_const(build_tss);
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

    unsafe { CS::set_reg(selectors.code) };
    unsafe { load_tss(selectors.tss) };
}

fn build_tss() -> TaskStateSegment {
    let mut tss = TaskStateSegment::new();
    let stacks_ptr = unsafe { core::ptr::addr_of!(IST_STACKS.0) } as *const u8;
    let base = VirtAddr::new(stacks_ptr as u64);

    tss.interrupt_stack_table[IST_INDEX_NMI as usize - 1] = base + IST_STACK_SIZE as u64;
    tss.interrupt_stack_table[IST_INDEX_DOUBLE_FAULT as usize - 1] =
        base + (IST_STACK_SIZE * 2) as u64;
    tss.interrupt_stack_table[IST_INDEX_MACHINE_CHECK as usize - 1] =
        base + (IST_STACK_SIZE * 3) as u64;

    tss
}

fn build_gdt() -> (GlobalDescriptorTable, GdtSelectors) {
    let mut gdt = GlobalDescriptorTable::new();
    let tss = &TSS;

    let code = gdt.append(Descriptor::kernel_code_segment());
    let data = gdt.append(Descriptor::kernel_data_segment());
    let tss_sel = gdt.append(Descriptor::tss_segment(tss));

    (
        gdt,
        GdtSelectors {
            code,
            _data: data,
            tss: tss_sel,
        },
    )
}
