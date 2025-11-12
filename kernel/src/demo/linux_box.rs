//! Static catalogue for the ad-hoc Linux Box demos embedded in the kernel image.

use crate::syscall::SyscallPolicy;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DemoKind {
    Linux,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DemoState {
    Ready,
}

impl DemoState {
    pub const fn as_str(self) -> &'static str {
        match self {
            DemoState::Ready => "ready",
        }
    }
}

pub struct LinuxDemoSpec {
    pub name: &'static str,
    pub kind: DemoKind,
    pub state: DemoState,
    pub default_policy: SyscallPolicy,
    pub cmd: &'static str,
    pub payload: &'static [u8],
}

pub const LINUX_DEMOS: &[LinuxDemoSpec] = &[
    LinuxDemoSpec {
        name: "demo1",
        kind: DemoKind::Linux,
        state: DemoState::Ready,
        default_policy: SyscallPolicy::Minimal,
        cmd: "./demo1.bin",
        payload: include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../bin/demo1.bin")),
    },
    LinuxDemoSpec {
        name: "demo2",
        kind: DemoKind::Linux,
        state: DemoState::Ready,
        default_policy: SyscallPolicy::Minimal,
        cmd: "./demo2.bin",
        payload: include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../bin/demo2.bin")),
    },
];
