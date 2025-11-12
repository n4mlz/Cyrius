use crate::arch::{Arch, api::ArchThread};
use crate::mem::addr::{MemPerm, VirtAddr};
use crate::process::ProcessId;

const IMAGE_REGION_BASE: usize = 0x0000_0040_0000_0000;
const IMAGE_SLOT_SIZE: usize = 0x0020_0000;
const IMAGE_MAX_SLOTS: usize = 256;

#[derive(Debug)]
pub enum LoaderError {
    OversizedPayload,
    MapFailure,
}

pub struct LoadedImage {
    entry: VirtAddr,
    image: <Arch as ArchThread>::UserImage,
}

impl LoadedImage {
    pub fn entry(&self) -> VirtAddr {
        self.entry
    }

    pub fn into_parts(self) -> (<Arch as ArchThread>::UserImage, VirtAddr) {
        (self.image, self.entry)
    }
}

pub fn load(
    pid: ProcessId,
    space: &<Arch as ArchThread>::AddressSpace,
    payload: &[u8],
) -> Result<LoadedImage, LoaderError> {
    if payload.len() > IMAGE_SLOT_SIZE {
        return Err(LoaderError::OversizedPayload);
    }
    let base = slot_base(pid);
    let image = <Arch as ArchThread>::map_user_image(space, base, payload, MemPerm::USER_RX)
        .map_err(|_| LoaderError::MapFailure)?;
    let entry = <Arch as ArchThread>::user_image_entry(&image);
    Ok(LoadedImage { entry, image })
}

fn slot_base(pid: ProcessId) -> VirtAddr {
    let slot = (pid as usize) % IMAGE_MAX_SLOTS;
    VirtAddr::new(IMAGE_REGION_BASE + slot * IMAGE_SLOT_SIZE)
}
