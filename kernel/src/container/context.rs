use alloc::sync::Arc;

use oci_spec::runtime::Spec;

use crate::fs::{Node, Vfs};

#[derive(Clone)]
pub struct ContainerContext {
    vfs: Arc<Vfs>,
    uts: Uts,
}

impl ContainerContext {
    pub fn new(vfs: Arc<Vfs>, uts: Uts) -> Self {
        Self { vfs, uts }
    }

    pub fn rootfs(&self) -> Arc<dyn Node> {
        self.vfs.root()
    }

    pub fn vfs(&self) -> Arc<Vfs> {
        self.vfs.clone()
    }

    pub fn uts(&self) -> Uts {
        self.uts
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Uts {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

impl Uts {
    pub fn default_host() -> Self {
        Self::build(UtsFields {
            sysname: "Linux",
            nodename: "cyrius",
            release: "0.0.1-alpha",
            version: "cyrius",
            machine: "x86_64",
            domainname: "",
        })
    }

    pub fn from_spec(spec: &Spec) -> Self {
        let nodename = spec.hostname().as_deref().unwrap_or("cyrius");
        let domainname = spec.domainname().as_deref().unwrap_or("");
        Self::build(UtsFields {
            sysname: "Linux",
            nodename,
            release: "0.0.1-alpha",
            version: "cyrius",
            machine: "x86_64",
            domainname,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                (self as *const Uts) as *const u8,
                core::mem::size_of::<Uts>(),
            )
        }
    }

    fn build(fields: UtsFields<'_>) -> Self {
        fn write_field(dst: &mut [u8; 65], src: &str) {
            let bytes = src.as_bytes();
            let len = dst.len().saturating_sub(1).min(bytes.len());
            dst[..len].copy_from_slice(&bytes[..len]);
            dst[len] = 0;
        }

        let mut uts = Self {
            sysname: [0; 65],
            nodename: [0; 65],
            release: [0; 65],
            version: [0; 65],
            machine: [0; 65],
            domainname: [0; 65],
        };
        write_field(&mut uts.sysname, fields.sysname);
        write_field(&mut uts.nodename, fields.nodename);
        write_field(&mut uts.release, fields.release);
        write_field(&mut uts.version, fields.version);
        write_field(&mut uts.machine, fields.machine);
        write_field(&mut uts.domainname, fields.domainname);
        uts
    }
}

struct UtsFields<'a> {
    sysname: &'a str,
    nodename: &'a str,
    release: &'a str,
    version: &'a str,
    machine: &'a str,
    domainname: &'a str,
}
