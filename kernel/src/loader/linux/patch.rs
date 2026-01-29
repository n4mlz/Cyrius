use crate::mem::addr::{VirtAddr, VirtIntoPtr};
use crate::mem::manager;
use crate::mem::paging::{PageTableOps, PhysMapper, TranslationError};
use crate::util::spinlock::SpinLock;
use core::fmt;
use core::mem::MaybeUninit;

/// Translate Linux `syscall` instructions to `int 0x80` so we can reuse the existing software
/// interrupt handler until `SYSCALL/SYSRET` is wired up.
///
/// This is a heuristic scan that may produce false positives/negatives because it does not
/// decode instruction boundaries. It uses simple byte patterns to reduce the chance of
/// rewriting immediate or displacement data.
pub fn rewrite_syscalls_in_table<T: PageTableOps>(
    base: VirtAddr,
    size: usize,
    table: &T,
) -> Result<(), TranslationError> {
    let mapper = manager::phys_mapper();
    let mut offset = 0usize;
    while offset + 1 < size {
        let addr = match base.as_raw().checked_add(offset) {
            Some(addr) => addr,
            None => return Err(TranslationError::NotMapped),
        };
        let virt = VirtAddr::new(addr);
        let phys = table.translate(virt)?;
        let ptr = unsafe { mapper.phys_to_virt(phys).into_mut_ptr() };
        let opcode = unsafe { core::ptr::read(ptr) };
        let next = unsafe { core::ptr::read(ptr.add(1)) };
        if opcode == 0x0F && next == 0x05 {
            record_syscall_found();
            if !matches_syscall_pattern(table, addr) {
                let context_start = addr.saturating_sub(CONTEXT_BYTES);
                let mut context = [0u8; WINDOW_BYTES];
                let context_ok =
                    read_bytes(table, VirtAddr::new(context_start), &mut context).is_ok();
                record_syscall_skipped(addr, context, context_ok);
                offset = offset.saturating_add(1);
                continue;
            }
            let context_start = addr.saturating_sub(CONTEXT_BYTES);
            let mut before = [0u8; WINDOW_BYTES];
            let mut after = [0u8; WINDOW_BYTES];
            let before_ok =
                read_bytes(table, VirtAddr::new(context_start), &mut before).is_ok();

            let prev_byte = if addr > 0 {
                read_byte(table, VirtAddr::new(addr - 1)).ok()
            } else {
                None
            };
            let next_byte = read_byte(table, VirtAddr::new(addr + 2)).ok();
            let boundary_hint = boundary_hint(prev_byte);

            unsafe {
                core::ptr::write(ptr, 0xCD);
                core::ptr::write(ptr.add(1), 0x80);
            }

            let after_ok = read_bytes(table, VirtAddr::new(context_start), &mut after).is_ok();
            record_rewrite(RewriteEntry {
                vaddr: addr,
                before,
                after,
                opcode_ok: opcode == 0x0F && next == 0x05,
                before_ok,
                after_ok,
                prev: prev_byte.unwrap_or(0),
                next: next_byte.unwrap_or(0),
                hint: boundary_hint,
            });
        }
        offset = offset.saturating_add(1);
    }
    Ok(())
}

pub fn begin_rewrite_report() {
    let mut tracker = REWRITE_TRACKER.lock();
    tracker.reset();
}

pub fn verify_rewrite_coverage<T: PageTableOps>(
    base: VirtAddr,
    size: usize,
    table: &T,
) -> Result<(), TranslationError> {
    const PROBE_START: usize = 0x4d7300;
    const PROBE_END: usize = 0x4d7400;

    let tracker = REWRITE_TRACKER.lock();
    if tracker.overflowed() {
        panic!("[loader] rewrite log overflow; cannot verify cd 80 coverage");
    }
    let mut offset = 0usize;
    while offset + 1 < size {
        let addr = match base.as_raw().checked_add(offset) {
            Some(addr) => addr,
            None => return Err(TranslationError::NotMapped),
        };
        if addr < PROBE_START || addr + 1 >= PROBE_END {
            offset = offset.saturating_add(1);
            continue;
        }
        let opcode = read_byte(table, VirtAddr::new(addr))?;
        let next = read_byte(table, VirtAddr::new(addr + 1))?;
        if opcode == 0xCD && next == 0x80 && !tracker.contains(addr) {
            panic!(
                "[loader] unexpected cd 80 at vaddr={:#x} (not in rewrite log)",
                addr
            );
        }
        offset = offset.saturating_add(1);
    }
    Ok(())
}

pub fn emit_rewrite_summary() {
    const PROBE_START: usize = 0x4d7300;
    const PROBE_END: usize = 0x4d7400;
    let tracker = REWRITE_TRACKER.lock();
    crate::println!(
        "[loader] rewrite summary found={} replaced={} skipped={} total={} stored={} min={:#x} max={:#x}",
        tracker.found_total,
        tracker.replaced_total,
        tracker.skipped_total,
        tracker.total,
        tracker.stored,
        tracker.min_addr(),
        tracker.max_addr()
    );

    crate::print!("[loader] rewrite vaddrs:");
    for idx in 0..tracker.stored {
        let entry = tracker.entry(idx);
        crate::print!(" {:#x}", entry.vaddr);
    }
    if tracker.overflowed() {
        crate::print!(" ... (truncated)");
    }
    crate::print!("\n");

    if tracker.skipped_total > 0 {
        crate::print!("[loader] rewrite skipped:");
        for idx in 0..tracker.skipped_stored {
            let entry = tracker.skipped_entry(idx);
            crate::print!(" {:#x}", entry.vaddr);
        }
        if tracker.skipped_overflowed() {
            crate::print!(" ... (truncated)");
        }
        crate::print!("\n");
        for idx in 0..tracker.skipped_stored {
            let entry = tracker.skipped_entry(idx);
            crate::println!(
                "[loader] rewrite skipped context vaddr={:#x} ok={} bytes=[{}]",
                entry.vaddr,
                entry.context_ok,
                HexBytes(&entry.context)
            );
        }
    }

    for idx in 0..tracker.stored {
        let entry = tracker.entry(idx);
        if entry.vaddr >= PROBE_START && entry.vaddr < PROBE_END {
            crate::println!(
                "[loader] rewrite probe vaddr={:#x} opcode_ok={} before_ok={} after_ok={} prev={:#04x} next={:#04x} hint={}",
                entry.vaddr,
                entry.opcode_ok,
                entry.before_ok,
                entry.after_ok,
                entry.prev,
                entry.next,
                entry.hint
            );
            crate::println!(
                "[loader] rewrite probe before=[{}] after=[{}]",
                HexBytes(&entry.before),
                HexBytes(&entry.after)
            );
        }
    }
}

pub fn dump_range<T: PageTableOps>(
    start: VirtAddr,
    len: usize,
    table: &T,
    label: &str,
) -> Result<(), TranslationError> {
    const LINE_BYTES: usize = 16;
    if len == 0 {
        return Ok(());
    }
    crate::println!(
        "[loader] dump {label} start={:#x} len={:#x}",
        start.as_raw(),
        len
    );
    let mut offset = 0usize;
    while offset < len {
        let line_len = core::cmp::min(LINE_BYTES, len - offset);
        let mut buf = [0u8; LINE_BYTES];
        read_bytes(
            table,
            VirtAddr::new(start.as_raw().saturating_add(offset)),
            &mut buf[..line_len],
        )?;
        crate::println!(
            "[loader] dump {:#x}: {}",
            start.as_raw().saturating_add(offset),
            HexBytes(&buf[..line_len])
        );
        offset = offset.saturating_add(line_len);
    }
    Ok(())
}

const CONTEXT_BYTES: usize = 8;
const WINDOW_BYTES: usize = 16;
const REWRITE_LOG_CAPACITY: usize = 4096;
const SKIPPED_LOG_CAPACITY: usize = 64;

static REWRITE_TRACKER: SpinLock<RewriteTracker> = SpinLock::new(RewriteTracker::new());

fn read_byte<T: PageTableOps>(table: &T, addr: VirtAddr) -> Result<u8, TranslationError> {
    let mapper = manager::phys_mapper();
    let phys = table.translate(addr)?;
    let ptr = unsafe { mapper.phys_to_virt(phys).into_ptr() };
    Ok(unsafe { core::ptr::read(ptr) })
}

fn read_bytes<T: PageTableOps>(
    table: &T,
    start: VirtAddr,
    out: &mut [u8],
) -> Result<(), TranslationError> {
    for (idx, slot) in out.iter_mut().enumerate() {
        let addr = start
            .as_raw()
            .checked_add(idx)
            .ok_or(TranslationError::NotMapped)?;
        *slot = read_byte(table, VirtAddr::new(addr))?;
    }
    Ok(())
}

fn boundary_hint(prev: Option<u8>) -> BoundaryHint {
    match prev {
        Some(0xC3) | Some(0xC2) | Some(0xCB) | Some(0xCA) | Some(0xCF) => BoundaryHint::Ret,
        Some(0x90) => BoundaryHint::Nop,
        Some(0xCC) => BoundaryHint::Int3,
        Some(0x0F) => BoundaryHint::Overlap,
        Some(0xE8) | Some(0xE9) | Some(0xEB) => BoundaryHint::Control,
        _ => BoundaryHint::Unknown,
    }
}

#[derive(Copy, Clone)]
enum BoundaryHint {
    Ret,
    Nop,
    Int3,
    Overlap,
    Control,
    Unknown,
}

impl fmt::Display for BoundaryHint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            BoundaryHint::Ret => "prev=ret",
            BoundaryHint::Nop => "prev=nop",
            BoundaryHint::Int3 => "prev=int3",
            BoundaryHint::Overlap => "prev=0f (overlap?)",
            BoundaryHint::Control => "prev=ctrl",
            BoundaryHint::Unknown => "prev=unknown",
        };
        f.write_str(text)
    }
}

struct HexBytes<'a>(&'a [u8]);

impl fmt::Display for HexBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, byte) in self.0.iter().enumerate() {
            if idx > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[derive(Copy, Clone)]
struct RewriteEntry {
    vaddr: usize,
    before: [u8; WINDOW_BYTES],
    after: [u8; WINDOW_BYTES],
    opcode_ok: bool,
    before_ok: bool,
    after_ok: bool,
    prev: u8,
    next: u8,
    hint: BoundaryHint,
}

struct RewriteTracker {
    entries: [MaybeUninit<RewriteEntry>; REWRITE_LOG_CAPACITY],
    stored: usize,
    total: usize,
    min: usize,
    max: usize,
    found_total: usize,
    replaced_total: usize,
    skipped_total: usize,
    skipped_entries: [MaybeUninit<SkippedEntry>; SKIPPED_LOG_CAPACITY],
    skipped_stored: usize,
}

impl RewriteTracker {
    const fn new() -> Self {
        Self {
            entries: [MaybeUninit::uninit(); REWRITE_LOG_CAPACITY],
            stored: 0,
            total: 0,
            min: usize::MAX,
            max: 0,
            found_total: 0,
            replaced_total: 0,
            skipped_total: 0,
            skipped_entries: [MaybeUninit::uninit(); SKIPPED_LOG_CAPACITY],
            skipped_stored: 0,
        }
    }

    fn reset(&mut self) {
        self.stored = 0;
        self.total = 0;
        self.min = usize::MAX;
        self.max = 0;
        self.found_total = 0;
        self.replaced_total = 0;
        self.skipped_total = 0;
        self.skipped_stored = 0;
    }

    fn record(&mut self, entry: RewriteEntry) {
        self.total = self.total.saturating_add(1);
        if entry.vaddr < self.min {
            self.min = entry.vaddr;
        }
        if entry.vaddr > self.max {
            self.max = entry.vaddr;
        }
        if self.stored < REWRITE_LOG_CAPACITY {
            self.entries[self.stored].write(entry);
            self.stored += 1;
        }
    }

    fn entry(&self, idx: usize) -> &RewriteEntry {
        unsafe { self.entries[idx].assume_init_ref() }
    }

    fn skipped_entry(&self, idx: usize) -> &SkippedEntry {
        unsafe { self.skipped_entries[idx].assume_init_ref() }
    }

    fn contains(&self, vaddr: usize) -> bool {
        for idx in 0..self.stored {
            if self.entry(idx).vaddr == vaddr {
                return true;
            }
        }
        false
    }

    fn overflowed(&self) -> bool {
        self.total > self.stored
    }

    fn skipped_overflowed(&self) -> bool {
        self.skipped_total > self.skipped_stored
    }

    fn min_addr(&self) -> usize {
        if self.total == 0 {
            0
        } else {
            self.min
        }
    }

    fn max_addr(&self) -> usize {
        if self.total == 0 {
            0
        } else {
            self.max
        }
    }
}

fn record_rewrite(entry: RewriteEntry) {
    let mut tracker = REWRITE_TRACKER.lock();
    tracker.replaced_total = tracker.replaced_total.saturating_add(1);
    tracker.record(entry);
}

fn record_syscall_found() {
    let mut tracker = REWRITE_TRACKER.lock();
    tracker.found_total = tracker.found_total.saturating_add(1);
}

fn record_syscall_skipped(vaddr: usize, context: [u8; WINDOW_BYTES], context_ok: bool) {
    let mut tracker = REWRITE_TRACKER.lock();
    tracker.skipped_total = tracker.skipped_total.saturating_add(1);
    if tracker.skipped_stored < SKIPPED_LOG_CAPACITY {
        let idx = tracker.skipped_stored;
        tracker.skipped_entries[idx].write(SkippedEntry {
            vaddr,
            context,
            context_ok,
        });
        tracker.skipped_stored = idx + 1;
    }
}

fn matches_syscall_pattern<T: PageTableOps>(table: &T, addr: usize) -> bool {
    // Patterns anchored to the 0f 05 at `addr`.
    // - b8 imm32 0f 05
    // - 48 c7 c0 imm32 0f 05
    // - 49 c7 c0 imm32 0f 05
    // - 31 c0 b0 imm8 0f 05
    if matches_b8_imm32_syscall(table, addr) {
        return true;
    }
    if matches_rex_c7_c0_imm32_syscall(table, addr, 0x48)
        || matches_rex_c7_c0_imm32_syscall(table, addr, 0x49)
    {
        return true;
    }
    if matches_xor_eax_mov_al_syscall(table, addr) {
        return true;
    }
    if matches_syscall_followed_by_ret(table, addr) {
        return true;
    }
    if matches_stack_arg_syscall(table, addr) {
        return true;
    }
    if matches_store_load_syscall(table, addr) {
        return true;
    }
    if matches_load_to_rdi_syscall(table, addr) {
        return true;
    }
    if matches_nop_padded_syscall(table, addr) {
        return true;
    }
    false
}

fn matches_b8_imm32_syscall<T: PageTableOps>(table: &T, addr: usize) -> bool {
    if addr < 5 {
        return false;
    }
    read_byte(table, VirtAddr::new(addr - 5))
        .map(|b| b == 0xB8)
        .unwrap_or(false)
}

fn matches_rex_c7_c0_imm32_syscall<T: PageTableOps>(
    table: &T,
    addr: usize,
    rex: u8,
) -> bool {
    if addr < 7 {
        return false;
    }
    let b0 = read_byte(table, VirtAddr::new(addr - 7));
    let b1 = read_byte(table, VirtAddr::new(addr - 6));
    let b2 = read_byte(table, VirtAddr::new(addr - 5));
    matches!(b0, Ok(v) if v == rex)
        && matches!(b1, Ok(v) if v == 0xC7)
        && matches!(b2, Ok(v) if v == 0xC0)
}

fn matches_xor_eax_mov_al_syscall<T: PageTableOps>(table: &T, addr: usize) -> bool {
    if addr < 4 {
        return false;
    }
    let b0 = read_byte(table, VirtAddr::new(addr - 4));
    let b1 = read_byte(table, VirtAddr::new(addr - 3));
    let b2 = read_byte(table, VirtAddr::new(addr - 2));
    matches!(b0, Ok(v) if v == 0x31)
        && matches!(b1, Ok(v) if v == 0xC0)
        && matches!(b2, Ok(v) if v == 0xB0)
}

fn matches_syscall_followed_by_ret<T: PageTableOps>(table: &T, addr: usize) -> bool {
    let next = read_byte(table, VirtAddr::new(addr + 2));
    matches!(next, Ok(v) if v == 0xC3 || v == 0xC2)
}

fn matches_stack_arg_syscall<T: PageTableOps>(table: &T, addr: usize) -> bool {
    if addr < 8 {
        return false;
    }
    let b0 = read_byte(table, VirtAddr::new(addr - 8));
    let b1 = read_byte(table, VirtAddr::new(addr - 7));
    let b2 = read_byte(table, VirtAddr::new(addr - 6));
    let b4 = read_byte(table, VirtAddr::new(addr - 4));
    let b5 = read_byte(table, VirtAddr::new(addr - 3));
    let b6 = read_byte(table, VirtAddr::new(addr - 2));
    matches!(b0, Ok(0x48))
        && matches!(b1, Ok(0x8b))
        && matches!(b2, Ok(0x75))
        && matches!(b4, Ok(0x48))
        && matches!(b5, Ok(0x8b))
        && matches!(b6, Ok(0x55))
}

fn matches_store_load_syscall<T: PageTableOps>(table: &T, addr: usize) -> bool {
    if addr < 8 {
        return false;
    }
    let b0 = read_byte(table, VirtAddr::new(addr - 8));
    let b1 = read_byte(table, VirtAddr::new(addr - 7));
    let b2 = read_byte(table, VirtAddr::new(addr - 6));
    let b4 = read_byte(table, VirtAddr::new(addr - 4));
    let b5 = read_byte(table, VirtAddr::new(addr - 3));
    let b6 = read_byte(table, VirtAddr::new(addr - 2));
    matches!(b0, Ok(0x48))
        && matches!(b1, Ok(0x89))
        && matches!(b2, Ok(0x7d))
        && matches!(b4, Ok(0x48))
        && matches!(b5, Ok(0x8b))
        && matches!(b6, Ok(0x45))
}

fn matches_load_to_rdi_syscall<T: PageTableOps>(table: &T, addr: usize) -> bool {
    if addr < 7 {
        return false;
    }
    let b0 = read_byte(table, VirtAddr::new(addr - 7));
    let b1 = read_byte(table, VirtAddr::new(addr - 6));
    let b2 = read_byte(table, VirtAddr::new(addr - 5));
    let b4 = read_byte(table, VirtAddr::new(addr - 3));
    let b5 = read_byte(table, VirtAddr::new(addr - 2));
    let b6 = read_byte(table, VirtAddr::new(addr - 1));
    matches!(b0, Ok(0x48))
        && matches!(b1, Ok(0x8b))
        && matches!(b2, Ok(v) if v == 0x55 || v == 0x75)
        && matches!(b4, Ok(0x48))
        && matches!(b5, Ok(0x89))
        && matches!(b6, Ok(0xd7))
}

fn matches_nop_padded_syscall<T: PageTableOps>(table: &T, addr: usize) -> bool {
    if addr < 8 {
        return false;
    }
    let next = read_byte(table, VirtAddr::new(addr + 2));
    if !matches!(next, Ok(0x90)) {
        return false;
    }
    for back in 1..=8 {
        let byte = read_byte(table, VirtAddr::new(addr - back));
        if !matches!(byte, Ok(0x00)) {
            return false;
        }
    }
    true
}

#[derive(Copy, Clone)]
struct SkippedEntry {
    vaddr: usize,
    context: [u8; WINDOW_BYTES],
    context_ok: bool,
}
