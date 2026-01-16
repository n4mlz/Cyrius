use crate::arch::Arch;
use crate::arch::api::ArchDevice;
use crate::util::stream::WriteOps;

pub fn write_console(bytes: &[u8]) -> usize {
    Arch::console().write(bytes).unwrap_or(0)
}
