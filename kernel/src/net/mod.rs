pub mod smoltcp;
pub mod consts;
pub mod runtime;
pub mod tcp;

#[cfg(not(test))]
use core::sync::atomic::{AtomicU64, Ordering};

pub use no_std_net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
pub use tcp::{TcpError, TcpListener, TcpStream};

/// IP address with CIDR prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetCidr {
    addr: IpAddr,
    prefix: u8,
}

impl NetCidr {
    pub const fn new(addr: IpAddr, prefix: u8) -> Self {
        Self { addr, prefix }
    }

    pub const fn addr(&self) -> IpAddr {
        self.addr
    }

    pub const fn prefix(&self) -> u8 {
        self.prefix
    }
}

#[cfg(not(test))]
static NET_PID: AtomicU64 = AtomicU64::new(0);

/// Spawn background networking tasks once the scheduler is ready.
#[cfg(not(test))]
pub fn spawn_background_tasks() {
    if NET_PID.load(Ordering::Acquire) != 0 {
        return;
    }

    let pid = match crate::process::PROCESS_TABLE.create_kernel_process("net") {
        Ok(pid) => pid,
        Err(err) => {
            crate::println!("[net] failed to create net process: {err:?}");
            return;
        }
    };
    NET_PID.store(pid, Ordering::Release);

    if let Err(err) = crate::thread::SCHEDULER.spawn_kernel_thread_for_process(
        pid,
        "net-poll",
        net_poll_loop,
    ) {
        crate::println!("[net] failed to spawn net poll thread: {err:?}");
    }
}

#[cfg(not(test))]
fn net_poll_loop() -> ! {
    match runtime::init() {
        Ok(()) | Err(runtime::NetError::AlreadyInitialised) => {}
        Err(err) => crate::println!("[net] runtime init failed: {err:?}"),
    }

    loop {
        let _ = runtime::poll_if_initialised();
        core::hint::spin_loop();
    }
}
