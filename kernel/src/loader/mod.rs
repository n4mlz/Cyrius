//! Program loading facilities.
//!
//! This module stays architecture-agnostic; architecture-specific glue (e.g., trap entry)
//! should live under `arch/`.

pub mod linux;

pub use crate::arch::api::{ArchLinuxElfPlatform, ArchPageTableAccess};
pub type DefaultLinuxElfPlatform =
    <crate::arch::Arch as crate::arch::api::ArchPlatformHooks>::LinuxElfPlatform;
