use core::sync::atomic::{AtomicU64, Ordering};

use crate::net::{IpAddr, Ipv4Addr, SocketAddr, TcpError, TcpListener, TcpStream};
use crate::process::{PROCESS_TABLE, ProcessError, ProcessId};
use crate::thread::{SCHEDULER, SpawnError};

const WEB_PORT: u16 = 12_345;
const BUFFER_SIZE: usize = 4096;

static WEB_PID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub enum WebServerError {
    Process(ProcessError),
    Spawn(SpawnError),
}

pub fn spawn_web_server() -> Result<(), WebServerError> {
    let pid = PROCESS_TABLE
        .create_kernel_process("web-server")
        .map_err(WebServerError::Process)?;
    WEB_PID.store(pid, Ordering::Release);

    SCHEDULER
        .spawn_kernel_thread_for_process(pid, "web-server-main", web_server_entry)
        .map(|_| ())
        .map_err(WebServerError::Spawn)
}

fn web_server_entry() -> ! {
    let pid = WEB_PID.load(Ordering::Acquire);
    web_server_loop(pid)
}

fn web_server_loop(_pid: ProcessId) -> ! {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), WEB_PORT);
    let mut listener = loop {
        match TcpListener::bind(addr) {
            Ok(listener) => break listener,
            Err(err) => {
                crate::println!("[web] bind failed: {err:?}");
                core::hint::spin_loop();
            }
        }
    };

    crate::println!("[web] echo server listening on 0.0.0.0:{WEB_PORT}");

    loop {
        match listener.accept() {
            Ok((stream, remote)) => {
                crate::println!("[web] accepted connection from {remote}");
                handle_connection(stream);
                crate::println!("[web] connection closed: {remote}");
            }
            Err(err) => {
                crate::println!("[web] accept error: {err:?}");
                core::hint::spin_loop();
            }
        }
    }
}

fn handle_connection(mut stream: TcpStream) {
    let mut buf = [0u8; BUFFER_SIZE];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(n) => n,
            Err(err) => {
                log_stream_error("read", err);
                return;
            }
        };

        if n == 0 {
            let _ = stream.close();
            return;
        }

        if let Err(err) = stream.write_all(&buf[..n]) {
            log_stream_error("write", err);
            let _ = stream.close();
            return;
        }
    }
}

fn log_stream_error(op: &str, err: TcpError) {
    crate::println!("[web] stream {op} error: {err:?}");
}
