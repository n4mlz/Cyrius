mod catalog;
mod loader;
mod runner;
mod shell;

pub use catalog::{DemoKind, DemoState, LINUX_DEMOS, LinuxDemoSpec};
pub use shell::spawn_shell_thread;
