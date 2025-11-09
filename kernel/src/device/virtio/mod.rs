//! Shared VirtIO transport primitives used by device drivers.

pub mod dma;
pub mod pci;
pub mod queue;

pub use dma::{DmaAllocator, DmaError, DmaRegion};
pub use pci::{PciTransport, PciTransportError};
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

/// Device status flag bits defined by the VirtIO specification.
pub mod status {
    pub const ACKNOWLEDGE: u32 = 1;
    pub const DRIVER: u32 = 1 << 1;
    pub const DRIVER_OK: u32 = 1 << 2;
    pub const FEATURES_OK: u32 = 1 << 3;
    pub const DEVICE_NEEDS_RESET: u32 = 1 << 6;
    pub const FAILED: u32 = 1 << 7;
}
