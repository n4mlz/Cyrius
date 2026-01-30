use alloc::vec;
use core::sync::atomic::{AtomicU16, Ordering};

use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp::{ConnectError, ListenError, RecvError, SendError, Socket, SocketBuffer};
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};

use crate::net::runtime::{self, NetError};
use crate::net::smoltcp::{to_no_std_endpoint, to_smoltcp_endpoint, to_smoltcp_ipv4};
use crate::net::{IpAddr, Ipv4Addr, SocketAddr};

const TCP_RX_BUFFER: usize = 16 * 1024;
const TCP_TX_BUFFER: usize = 16 * 1024;
const EPHEMERAL_START: u16 = 49_152;
const EPHEMERAL_END: u16 = 65_535;

static NEXT_EPHEMERAL_PORT: AtomicU16 = AtomicU16::new(EPHEMERAL_START);
#[derive(Debug)]
pub enum TcpError {
    Net(NetError),
    UnsupportedAddressFamily,
    Listen(ListenError),
    Connect(ConnectError),
    Send(SendError),
    Recv(RecvError),
    Closed,
    ProgressTimeout,
}

impl From<NetError> for TcpError {
    fn from(value: NetError) -> Self {
        Self::Net(value)
    }
}

pub struct TcpListener {
    local_addr: SocketAddr,
    handle: SocketHandle,
}

impl TcpListener {
    pub fn bind(addr: SocketAddr) -> Result<Self, TcpError> {
        ensure_runtime()?;
        let local = to_smoltcp_listen_endpoint(addr)?;

        let handle = runtime::with_runtime(|rt| {
            let sockets = rt.stack_mut().sockets_mut();
            let mut socket = new_tcp_socket();
            socket.listen(local).map_err(TcpError::Listen)?;
            Ok::<SocketHandle, TcpError>(sockets.add(socket))
        })??;

        Ok(Self {
            local_addr: addr,
            handle,
        })
    }

    /// Attempt a single accept step.
    ///
    /// Returns `Ok(None)` when no connection is ready yet.
    pub fn try_accept(&mut self) -> Result<Option<(TcpStream, SocketAddr)>, TcpError> {
        ensure_runtime()?;
        let local_addr = self.local_addr;

        let accepted = runtime::with_runtime(|rt| {
            let _ = rt.poll();
            let sockets = rt.stack_mut().sockets_mut();
            let socket = sockets.get_mut::<Socket>(self.handle);

            if !socket.is_active() {
                return Ok::<Option<(SocketHandle, SocketAddr)>, TcpError>(None);
            }

            let remote = socket.remote_endpoint().and_then(to_no_std_endpoint);
            let Some(remote) = remote else {
                return Ok::<Option<(SocketHandle, SocketAddr)>, TcpError>(None);
            };

            let new_handle = listen_on(sockets, local_addr)?;
            let accepted_handle = core::mem::replace(&mut self.handle, new_handle);
            Ok(Some((accepted_handle, remote)))
        })??;

        Ok(accepted.map(|(handle, remote)| (TcpStream { handle }, remote)))
    }

    pub fn accept(&mut self) -> Result<(TcpStream, SocketAddr), TcpError> {
        loop {
            if let Some(pair) = self.try_accept()? {
                return Ok(pair);
            }
            core::hint::spin_loop();
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        let _ = runtime::with_runtime(|rt| {
            rt.stack_mut().sockets_mut().remove(self.handle);
        });
    }
}

pub struct TcpStream {
    handle: SocketHandle,
}

impl TcpStream {
    #[allow(unreachable_patterns)]
    pub fn connect(remote: SocketAddr) -> Result<Self, TcpError> {
        ensure_runtime()?;
        let remote_endpoint =
            to_smoltcp_endpoint(remote).ok_or(TcpError::UnsupportedAddressFamily)?;

        let handle = runtime::with_runtime(|rt| {
            let sockets = rt.stack_mut().sockets_mut();
            let socket = new_tcp_socket();
            sockets.add(socket)
        })?;

        let local_ip = runtime::with_runtime(|rt| {
            let iface = rt.stack_mut().interface_mut();
            iface
                .ip_addrs()
                .iter()
                .find_map(|cidr| match cidr.address() {
                    smoltcp::wire::IpAddress::Ipv4(addr) => Some(addr),
                    _ => None,
                })
        })?
        .ok_or(TcpError::UnsupportedAddressFamily)?;

        let local_endpoint = IpEndpoint::new(smoltcp::wire::IpAddress::Ipv4(local_ip), next_port());

        let connect_result = runtime::with_runtime(|rt| {
            let _ = rt.poll();
            rt.stack_mut().with_context_and_sockets(|cx, sockets| {
                let socket = sockets.get_mut::<Socket>(handle);
                if socket.is_active() {
                    return Ok(());
                }
                socket
                    .connect(cx, remote_endpoint, local_endpoint)
                    .map_err(TcpError::Connect)
            })
        })?;

        connect_result?;

        let mut stream = Self { handle };
        for _ in 0..50_000 {
            if stream.is_active()? {
                return Ok(stream);
            }
            let _ = runtime::poll();
            core::hint::spin_loop();
        }

        Err(TcpError::ProgressTimeout)
    }

    pub fn is_active(&mut self) -> Result<bool, TcpError> {
        ensure_runtime()?;
        runtime::with_runtime(|rt| {
            let _ = rt.poll();
            let socket = rt.stack_mut().sockets_mut().get_mut::<Socket>(self.handle);
            socket.is_active()
        })
        .map_err(TcpError::Net)
    }

    /// Attempt a single read step.
    ///
    /// Returns `Ok(None)` if the socket would block.
    pub fn try_read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, TcpError> {
        ensure_runtime()?;
        runtime::with_runtime(|rt| {
            let _ = rt.poll();
            let socket = rt.stack_mut().sockets_mut().get_mut::<Socket>(self.handle);

            if socket.can_recv() {
                return socket.recv_slice(buf).map(Some).map_err(TcpError::Recv);
            }

            if !socket.may_recv() {
                return Ok(Some(0));
            }

            Ok(None)
        })?
    }

    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, TcpError> {
        loop {
            if let Some(n) = self.try_read(buf)? {
                return Ok(n);
            }
            core::hint::spin_loop();
        }
    }

    /// Attempt a single write step.
    ///
    /// Returns `Ok(None)` if the socket would block.
    pub fn try_write(&mut self, buf: &[u8]) -> Result<Option<usize>, TcpError> {
        ensure_runtime()?;
        runtime::with_runtime(|rt| {
            let _ = rt.poll();
            let socket = rt.stack_mut().sockets_mut().get_mut::<Socket>(self.handle);

            if socket.can_send() {
                return socket.send_slice(buf).map(Some).map_err(TcpError::Send);
            }

            if !socket.may_send() {
                return Err(TcpError::Closed);
            }

            Ok(None)
        })?
    }

    pub fn write_all(&mut self, mut buf: &[u8]) -> Result<(), TcpError> {
        while !buf.is_empty() {
            match self.try_write(buf)? {
                Some(0) => return Err(TcpError::Closed),
                Some(n) => buf = &buf[n..],
                None => core::hint::spin_loop(),
            }
        }
        Ok(())
    }

    pub fn close(&mut self) -> Result<(), TcpError> {
        ensure_runtime()?;
        runtime::with_runtime(|rt| {
            let socket = rt.stack_mut().sockets_mut().get_mut::<Socket>(self.handle);
            socket.close();
            let _ = rt.poll();
        })?;
        Ok(())
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let _ = self.close();
        let _ = runtime::defer_socket_close(self.handle);
    }
}

fn ensure_runtime() -> Result<(), TcpError> {
    match runtime::init() {
        Ok(()) | Err(NetError::AlreadyInitialised) => Ok(()),
        Err(err) => Err(TcpError::Net(err)),
    }
}

fn new_tcp_socket() -> Socket<'static> {
    let rx = SocketBuffer::new(vec![0; TCP_RX_BUFFER]);
    let tx = SocketBuffer::new(vec![0; TCP_TX_BUFFER]);
    Socket::new(rx, tx)
}

fn listen_on(
    sockets: &mut smoltcp::iface::SocketSet<'static>,
    addr: SocketAddr,
) -> Result<SocketHandle, TcpError> {
    let local = to_smoltcp_listen_endpoint(addr)?;
    let mut socket = new_tcp_socket();
    socket.listen(local).map_err(TcpError::Listen)?;
    Ok(sockets.add(socket))
}

fn to_smoltcp_listen_endpoint(addr: SocketAddr) -> Result<IpListenEndpoint, TcpError> {
    let port = addr.port();
    match addr.ip() {
        IpAddr::V4(v4) => {
            if v4 == Ipv4Addr::UNSPECIFIED {
                Ok(IpListenEndpoint::from(port))
            } else {
                Ok(IpListenEndpoint::from((to_smoltcp_ipv4(v4), port)))
            }
        }
        IpAddr::V6(_) => Err(TcpError::UnsupportedAddressFamily),
    }
}

fn next_port() -> u16 {
    let current = NEXT_EPHEMERAL_PORT.fetch_add(1, Ordering::AcqRel);
    if current == EPHEMERAL_END || current < EPHEMERAL_START {
        NEXT_EPHEMERAL_PORT.store(EPHEMERAL_START, Ordering::Release);
        EPHEMERAL_START
    } else {
        current
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use smoltcp::iface::SocketHandle;
    use smoltcp::socket::tcp::{
        RecvError, Socket as RawTcpSocket, SocketBuffer as RawTcpSocketBuffer,
    };
    use smoltcp::wire::{IpAddress, IpEndpoint};

    use crate::net::runtime::{self, TestNetworkDevice};
    use crate::net::smoltcp::{SmoltcpStack, to_smoltcp_ipv4};
    use crate::net::{IpAddr, Ipv4Addr, NetCidr, SocketAddr};
    use crate::println;
    use crate::test::kernel_test_case;

    use super::TcpListener;

    const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
    const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 16);
    const PORT: u16 = 12_345;

    #[kernel_test_case]
    fn tcp_listener_accepts_and_echoes() {
        println!("[test] tcp_listener_accepts_and_echoes");

        runtime::reset_for_tests();
        let (server_dev, client_dev) = TestNetworkDevice::pair();
        runtime::init_for_tests(server_dev);

        let client_addr = NetCidr::new(IpAddr::V4(CLIENT_IP), 24);
        let mut client_stack = SmoltcpStack::new(client_dev, &[client_addr]);

        let server_addr = SocketAddr::new(IpAddr::V4(SERVER_IP), PORT);
        let mut listener = TcpListener::bind(server_addr).expect("bind listener");

        let mut client_socket = RawTcpSocket::new(
            RawTcpSocketBuffer::new(vec![0; 8 * 1024]),
            RawTcpSocketBuffer::new(vec![0; 8 * 1024]),
        );
        let client_handle = client_stack.sockets_mut().add(client_socket);

        let local_endpoint = IpEndpoint::new(IpAddress::Ipv4(to_smoltcp_ipv4(CLIENT_IP)), 40_000);
        let remote_endpoint = IpEndpoint::new(IpAddress::Ipv4(to_smoltcp_ipv4(SERVER_IP)), PORT);

        client_stack
            .with_context_and_sockets(|cx, sockets| {
                sockets.get_mut::<RawTcpSocket>(client_handle).connect(
                    cx,
                    remote_endpoint,
                    local_endpoint,
                )
            })
            .expect("client connect");

        let mut accepted = None;
        for _ in 0..200_000 {
            poll_both(&mut client_stack);
            if let Some((stream, _addr)) = listener.try_accept().expect("try_accept") {
                accepted = Some(stream);
                break;
            }
        }
        let mut stream = accepted.expect("server accepted connection");

        let payload = b"hello from client";
        send_from_client(&mut client_stack, client_handle, payload);

        let mut read_buf = [0u8; 64];
        let read = loop_with_poll(&mut client_stack, || stream.try_read(&mut read_buf))
            .expect("server read result");
        assert_eq!(read, payload.len());
        assert_eq!(&read_buf[..read], payload);

        let mut written = 0usize;
        while written < read {
            poll_both(&mut client_stack);
            if let Some(n) = stream
                .try_write(&read_buf[written..read])
                .expect("server try_write")
            {
                written += n;
            }
        }

        let mut echoed = [0u8; 64];
        let echoed_len = recv_on_client(&mut client_stack, client_handle, &mut echoed);
        assert_eq!(echoed_len, payload.len());
        assert_eq!(&echoed[..echoed_len], payload);
    }

    #[kernel_test_case]
    fn tcp_close_waits_for_tx_drain() {
        println!("[test] tcp_close_waits_for_tx_drain");

        runtime::reset_for_tests();
        let (server_dev, client_dev) = TestNetworkDevice::pair();
        runtime::init_for_tests(server_dev);

        let client_addr = NetCidr::new(IpAddr::V4(CLIENT_IP), 24);
        let mut client_stack = SmoltcpStack::new(client_dev, &[client_addr]);

        let server_addr = SocketAddr::new(IpAddr::V4(SERVER_IP), PORT);
        let mut listener = TcpListener::bind(server_addr).expect("bind listener");

        let mut client_socket = RawTcpSocket::new(
            RawTcpSocketBuffer::new(vec![0; 128 * 1024]),
            RawTcpSocketBuffer::new(vec![0; 128 * 1024]),
        );
        let client_handle = client_stack.sockets_mut().add(client_socket);

        let local_endpoint = IpEndpoint::new(IpAddress::Ipv4(to_smoltcp_ipv4(CLIENT_IP)), 40_001);
        let remote_endpoint = IpEndpoint::new(IpAddress::Ipv4(to_smoltcp_ipv4(SERVER_IP)), PORT);

        client_stack
            .with_context_and_sockets(|cx, sockets| {
                sockets.get_mut::<RawTcpSocket>(client_handle).connect(
                    cx,
                    remote_endpoint,
                    local_endpoint,
                )
            })
            .expect("client connect");

        let mut accepted = None;
        for _ in 0..200_000 {
            poll_both(&mut client_stack);
            if let Some((stream, _addr)) = listener.try_accept().expect("try_accept") {
                accepted = Some(stream);
                break;
            }
        }
        let mut stream = accepted.expect("server accepted connection");

        let payload = vec![0xAC; 64 * 1024];
        let mut sent = 0usize;
        for _ in 0..500_000 {
            poll_both(&mut client_stack);
            if let Some(n) = stream
                .try_write(&payload[sent..])
                .expect("server try_write")
            {
                sent += n;
                if sent == payload.len() {
                    break;
                }
            }
        }
        assert_eq!(sent, payload.len());
        stream.close().expect("server close");

        let mut received = Vec::with_capacity(payload.len());
        let mut finished = false;
        for _ in 0..500_000 {
            poll_both(&mut client_stack);
            let socket = client_stack
                .sockets_mut()
                .get_mut::<RawTcpSocket>(client_handle);
            if socket.can_recv() {
                let mut buf = [0u8; 4096];
                match socket.recv_slice(&mut buf) {
                    Ok(n) => {
                        received.extend_from_slice(&buf[..n]);
                        if received.len() == payload.len() {
                            continue;
                        }
                    }
                    Err(RecvError::Finished) => {
                        finished = true;
                        break;
                    }
                    Err(err) => panic!("client recv error: {:?}", err),
                }
            } else if !socket.may_recv() {
                finished = true;
                break;
            }
        }
        assert_eq!(received.len(), payload.len());
        assert!(finished, "client did not observe FIN");
    }

    fn poll_both(client_stack: &mut SmoltcpStack<TestNetworkDevice>) {
        let _ = client_stack.poll();
        let _ = runtime::poll();
    }

    fn loop_with_poll<T>(
        client_stack: &mut SmoltcpStack<TestNetworkDevice>,
        mut f: impl FnMut() -> Result<Option<T>, super::TcpError>,
    ) -> Result<T, super::TcpError> {
        for _ in 0..200_000 {
            poll_both(client_stack);
            if let Some(value) = f()? {
                return Ok(value);
            }
        }
        panic!("timed out waiting for TCP progress");
    }

    fn send_from_client(
        client_stack: &mut SmoltcpStack<TestNetworkDevice>,
        handle: SocketHandle,
        payload: &[u8],
    ) {
        let mut sent = 0usize;
        for _ in 0..200_000 {
            poll_both(client_stack);
            let socket = client_stack.sockets_mut().get_mut::<RawTcpSocket>(handle);
            if socket.can_send() {
                sent += socket.send_slice(&payload[sent..]).expect("client send");
                if sent == payload.len() {
                    return;
                }
            }
        }
        panic!("client send timed out");
    }

    fn recv_on_client(
        client_stack: &mut SmoltcpStack<TestNetworkDevice>,
        handle: SocketHandle,
        out: &mut [u8],
    ) -> usize {
        for _ in 0..200_000 {
            poll_both(client_stack);
            let socket = client_stack.sockets_mut().get_mut::<RawTcpSocket>(handle);
            if socket.can_recv() {
                return socket.recv_slice(out).expect("client recv");
            }
        }
        panic!("client recv timed out");
    }
}
