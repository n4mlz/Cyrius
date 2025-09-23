use crate::arch::{
    Arch,
    api::{ArchMmu, ArchPlatform, KernelLayoutRequest, KernelVirtLayout},
};
use crate::boot::{BootInfo, MemoryMap, PhysicalRegionKind};
use crate::mem::addr::{Addr, AddrRange, PhysAddr};
use crate::mem::paging::MapError;
use crate::util::spinlock::SpinLock;

const HEAP_ALIGNMENT: usize = 0x1000;

#[derive(Copy, Clone, Debug)]
struct PlannedLayout {
    heap_phys: AddrRange<PhysAddr>,
    virt_layout: KernelVirtLayout,
}

/// Coordinates kernel memory planning between the portable core and the architecture MMU.
///
/// The planner selects physical regions (such as the kernel heap), asks the architecture MMU to
/// realise the requested virtual layout, and exposes the resulting mappings to subsystems like the
/// kernel heap without forcing them to depend on MMU internals.
pub struct KernelMemoryPlanner {
    planned: SpinLock<Option<PlannedLayout>>,
}

impl KernelMemoryPlanner {
    pub const fn new() -> Self {
        Self {
            planned: SpinLock::new(None),
        }
    }

    pub fn global() -> &'static Self {
        &PLANNER
    }

    /// Plans the kernel's memory layout based on the provided boot information.
    ///
    /// As an incidental effect, initializes the ArchMmu.
    /// Maintains its own record of the kernel's address layout as mapped by the MMU.
    pub fn plan(
        &self,
        boot_info: &BootInfo<<Arch as ArchPlatform>::ArchBootInfo>,
    ) -> Result<(), MapError> {
        if self.planned.lock().is_some() {
            return Ok(());
        }

        let heap_phys = select_heap_region(boot_info.memory_map);
        let virt_layout = Arch::mmu()
            .prepare_kernel_layout(boot_info, KernelLayoutRequest::new(heap_phys, true))?;

        let mut guard = self.planned.lock();
        if guard.is_none() {
            *guard = Some(PlannedLayout {
                heap_phys,
                virt_layout,
            });
        }

        Ok(())
    }

    pub fn heap_phys(&self) -> Option<AddrRange<PhysAddr>> {
        let guard = self.planned.lock();
        guard.as_ref().map(|layout| layout.heap_phys)
    }

    pub fn layout(&self) -> Option<KernelVirtLayout> {
        let guard = self.planned.lock();
        guard.as_ref().map(|layout| layout.virt_layout)
    }
}

fn select_heap_region(map: MemoryMap<'_>) -> AddrRange<PhysAddr> {
    debug_assert!(HEAP_ALIGNMENT.is_power_of_two());

    map.iter()
        .filter(|region| region.kind == PhysicalRegionKind::Usable)
        .filter_map(|region| {
            let aligned_start = region.range.start.align_up(HEAP_ALIGNMENT);
            let region_end = region.range.end.as_usize();
            let start = aligned_start.as_usize();
            if start >= region_end {
                return None;
            }

            let available = region_end - start;
            let usable = available & !(HEAP_ALIGNMENT - 1);
            if usable == 0 {
                return None;
            }

            let end = start.checked_add(usable)?;

            Some((
                usable,
                AddrRange {
                    start: aligned_start,
                    end: PhysAddr::from_usize(end),
                },
            ))
        })
        .max_by_key(|(usable, _)| *usable)
        .map(|(_, range)| range)
        .expect("no suitable usable memory region found for heap")
}

static PLANNER: KernelMemoryPlanner = KernelMemoryPlanner::new();
