use alloc::string::ToString;
use alloc::sync::Arc;

use crate::device::block::{BlockDevice, BlockDeviceProvider, SharedBlockDevice};
use crate::device::virtio::block::VirtioBlockProvider;

use super::probe::{Fat32Probe, FileSystemProbe};
use super::{Node, VfsPath, memfs::MemDirectory, mount_at, mount_root};

pub fn init_filesystems() {
    init_filesystems_with(&VirtioBlockProvider, &Fat32Probe);
}

fn init_filesystems_with<P, F>(provider: &P, probe: &F)
where
    P: BlockDeviceProvider,
    P::Device: BlockDevice + Send,
    F: FileSystemProbe<P::Device>,
{
    let root = MemDirectory::new();
    mount_root(root.clone()).expect("mount memfs root");
    let mut best: Option<(u64, Arc<dyn Node>, alloc::string::String)> = None;
    provider.with_devices(|devices| {
        for dev in devices {
            let shared = SharedBlockDevice::from_arc(dev.clone());
            let name = shared.label().to_string();
            let capacity = shared.num_blocks();
            match probe.probe(shared) {
                Ok(root_dir) => match &best {
                    Some((best_cap, _, _)) if *best_cap >= capacity => {}
                    _ => best = Some((capacity, root_dir, name)),
                },
                Err(err) => crate::println!("[vfs] skipped {name}: {:?}", err),
            };
        }
    });

    let mut mounted = false;
    if let Some((cap, root_dir, name)) = best {
        let mount_path = VfsPath::parse("/mnt").expect("mount path");
        if mount_at(mount_path, root_dir).is_ok() {
            crate::println!("[vfs] mounted FAT32 at /mnt from {name} ({} blocks)", cap);
            mounted = true;
        }
    }

    if !mounted {
        crate::println!("[vfs] no FAT32 root mounted");
    }
}
