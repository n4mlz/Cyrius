use core::convert::TryFrom;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::mem::addr::{PhysAddr, VirtAddr};
use crate::mem::paging::PhysMapper;

#[derive(Clone, Copy, Debug)]
pub struct OffsetMapper {
    offset: u64,
}

impl OffsetMapper {
    pub const fn new(offset: u64) -> Self {
        Self { offset }
    }

    pub const fn offset(&self) -> u64 {
        self.offset
    }
}

impl PhysMapper for OffsetMapper {
    unsafe fn phys_to_virt(&self, addr: PhysAddr) -> VirtAddr {
        let phys = addr.as_raw() as u64;
        let virt = phys
            .checked_add(self.offset)
            .expect("physical to virtual translation overflow");
        VirtAddr::new(usize::try_from(virt).expect("virtual address exceeds usize"))
    }

    fn virt_to_phys(&self, addr: VirtAddr) -> PhysAddr {
        let virt = addr.as_raw() as u64;
        let phys = virt
            .checked_sub(self.offset)
            .expect("virtual address below physical mapping window");
        PhysAddr::new(usize::try_from(phys).expect("physical address exceeds usize"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysMapperInitError {
    AlreadyInitialised,
    MissingOffset,
}

pub struct GlobalPhysMapper {
    offset: AtomicU64,
    initialised: AtomicBool,
}

impl GlobalPhysMapper {
    pub const fn uninit() -> Self {
        Self {
            offset: AtomicU64::new(0),
            initialised: AtomicBool::new(false),
        }
    }

    pub fn init(&self, offset: Option<u64>) -> Result<(), PhysMapperInitError> {
        let offset = offset.ok_or(PhysMapperInitError::MissingOffset)?;
        if self.initialised.load(Ordering::Acquire) {
            return Err(PhysMapperInitError::AlreadyInitialised);
        }
        self.offset.store(offset, Ordering::Release);
        self.initialised.store(true, Ordering::Release);
        Ok(())
    }

    pub fn mapper(&self) -> OffsetMapper {
        assert!(
            self.initialised.load(Ordering::Acquire),
            "physical mapper not initialised"
        );
        let offset = self.offset.load(Ordering::Acquire);
        OffsetMapper::new(offset)
    }
}

pub static PHYS_MAPPER: GlobalPhysMapper = GlobalPhysMapper::uninit();
