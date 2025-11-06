//! Shared VirtIO transport primitives used by device drivers.

pub mod mmio;
pub mod queue;

pub use mmio::{MmioConfig, MmioDevice, MmioError};
pub use queue::{VirtQueueLayout, VirtQueueRegion};

/// Standard VirtIO device identifiers.
pub mod device_id {
    /// Block device identifier expected by virtio-blk.
    pub const BLOCK: u32 = 2;
}

/// Feature bits shared by VirtIO transports.
pub mod features {
    /// Negotiation bit indicating compliance with the modern VirtIO specification.
    pub const VERSION_1: u64 = 1 << 32;
    /// Enables writeback cache management for block devices.
    pub const WRITEBACK: u64 = 1 << 9;
}
