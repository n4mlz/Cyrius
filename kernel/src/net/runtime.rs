#[cfg(test)]
use alloc::sync::Arc;
use alloc::vec::Vec;

use smoltcp::iface::SocketHandle;

use crate::device::net::{LinkState, NetworkDevice, SharedNetworkDevice};
use crate::device::virtio::net::{VirtioNetError, VirtioPciNetDevice};
use crate::device::{Device, DeviceType};
use crate::net::consts::{DEFAULT_GATEWAY, DEFAULT_IPV4};
use crate::net::smoltcp::{SmoltcpStack, to_smoltcp_ipv4};
use crate::util::lazylock::LazyLock;
use crate::util::spinlock::SpinLock;

static NET_RUNTIME: LazyLock<SpinLock<Option<NetRuntime>>> =
    LazyLock::new_const(|| SpinLock::new(None));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    AlreadyInitialised,
    NotInitialised,
    NoDevice,
    Route(smoltcp::iface::RouteTableFull),
}

pub struct NetRuntime {
    stack: SmoltcpStack<NetDevice>,
    closing: Vec<SocketHandle>,
}

impl NetRuntime {
    fn new(device: NetDevice) -> Result<Self, NetError> {
        let mut stack = SmoltcpStack::new(device, &[DEFAULT_IPV4]);
        let gateway = to_smoltcp_ipv4(DEFAULT_GATEWAY);
        stack
            .interface_mut()
            .routes_mut()
            .add_default_ipv4_route(gateway)
            .map_err(NetError::Route)?;
        Ok(Self {
            stack,
            closing: Vec::new(),
        })
    }

    pub fn poll(&mut self) -> smoltcp::iface::PollResult {
        let result = self.stack.poll();
        self.reap_closed_sockets();
        result
    }

    pub fn stack_mut(&mut self) -> &mut SmoltcpStack<NetDevice> {
        &mut self.stack
    }

    fn defer_close(&mut self, handle: SocketHandle) {
        if self.closing.contains(&handle) {
            return;
        }
        self.closing.push(handle);
    }

    fn reap_closed_sockets(&mut self) {
        let mut idx = 0;
        while idx < self.closing.len() {
            let handle = self.closing[idx];
            let socket = self
                .stack
                .sockets_mut()
                .get_mut::<smoltcp::socket::tcp::Socket>(handle);
            let pending = socket.send_queue();
            let state = socket.state();
            let remove = pending == 0
                && matches!(
                    state,
                    smoltcp::socket::tcp::State::Closed | smoltcp::socket::tcp::State::TimeWait
                );
            if remove {
                let _ = self.stack.sockets_mut().remove(handle);
                self.closing.swap_remove(idx);
            } else {
                idx += 1;
            }
        }
    }
}

pub fn init() -> Result<(), NetError> {
    let mut guard = NET_RUNTIME.get().lock();
    if guard.is_some() {
        return Err(NetError::AlreadyInitialised);
    }

    let device = crate::device::virtio::net::with_devices(|devices| devices.first().cloned())
        .ok_or(NetError::NoDevice)?;

    let shared = SharedNetworkDevice::from_arc(device);
    let runtime = NetRuntime::new(NetDevice::virtio(shared))?;
    *guard = Some(runtime);
    Ok(())
}

pub fn with_runtime<R>(f: impl FnOnce(&mut NetRuntime) -> R) -> Result<R, NetError> {
    let mut guard = NET_RUNTIME.get().lock();
    let runtime = guard.as_mut().ok_or(NetError::NotInitialised)?;
    Ok(f(runtime))
}

pub fn poll() -> Result<smoltcp::iface::PollResult, NetError> {
    with_runtime(NetRuntime::poll)
}

pub fn poll_if_initialised() -> bool {
    let mut guard = NET_RUNTIME.get().lock();
    let Some(runtime) = guard.as_mut() else {
        return false;
    };
    let _ = runtime.poll();
    true
}

pub fn is_initialised() -> bool {
    let guard = NET_RUNTIME.get().lock();
    guard.is_some()
}

pub fn defer_socket_close(handle: SocketHandle) -> Result<(), NetError> {
    with_runtime(|rt| rt.defer_close(handle))
}

#[derive(Debug)]
pub enum NetDeviceError {
    Virtio(VirtioNetError),
    #[cfg(test)]
    Test(()),
}

/// Concrete network device used by the global runtime.
///
/// This enum keeps the runtime monomorphic while still allowing tests to inject
/// deterministic virtual devices.
pub enum NetDevice {
    Virtio(SharedNetworkDevice<VirtioPciNetDevice>),
    #[cfg(test)]
    Test(TestNetworkDevice),
}

impl NetDevice {
    fn virtio(device: SharedNetworkDevice<VirtioPciNetDevice>) -> Self {
        Self::Virtio(device)
    }

    #[cfg(test)]
    fn test(device: TestNetworkDevice) -> Self {
        Self::Test(device)
    }
}

impl Device for NetDevice {
    fn name(&self) -> &str {
        match self {
            NetDevice::Virtio(device) => device.name(),
            #[cfg(test)]
            NetDevice::Test(device) => device.name(),
        }
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Network
    }
}

impl NetworkDevice for NetDevice {
    type Error = NetDeviceError;

    fn mac_address(&self) -> [u8; 6] {
        match self {
            NetDevice::Virtio(device) => device.mac_address(),
            #[cfg(test)]
            NetDevice::Test(device) => device.mac_address(),
        }
    }

    fn mtu(&self) -> usize {
        match self {
            NetDevice::Virtio(device) => device.mtu(),
            #[cfg(test)]
            NetDevice::Test(device) => device.mtu(),
        }
    }

    fn link_state(&self) -> LinkState {
        match self {
            NetDevice::Virtio(device) => device.link_state(),
            #[cfg(test)]
            NetDevice::Test(device) => device.link_state(),
        }
    }

    fn transmit_frame(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        match self {
            NetDevice::Virtio(device) => {
                device.transmit_frame(frame).map_err(NetDeviceError::Virtio)
            }
            #[cfg(test)]
            NetDevice::Test(device) => device
                .transmit_frame(frame)
                .map_err(|_| NetDeviceError::Test(())),
        }
    }

    fn receive_frame(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        match self {
            NetDevice::Virtio(device) => {
                device.receive_frame(buffer).map_err(NetDeviceError::Virtio)
            }
            #[cfg(test)]
            NetDevice::Test(device) => device
                .receive_frame(buffer)
                .map_err(|_| NetDeviceError::Test(())),
        }
    }
}

#[cfg(test)]
pub fn init_for_tests(device: TestNetworkDevice) {
    let mut guard = NET_RUNTIME.get().lock();
    let runtime = NetRuntime::new(NetDevice::test(device)).expect("test runtime init");
    *guard = Some(runtime);
}

#[cfg(test)]
pub fn reset_for_tests() {
    let mut guard = NET_RUNTIME.get().lock();
    *guard = None;
}

#[cfg(test)]
#[derive(Clone)]
pub struct TestNetworkDevice {
    inner: Arc<SpinLock<TestWireEndpoint>>,
}

#[cfg(test)]
impl TestNetworkDevice {
    pub fn pair() -> (Self, Self) {
        let wire = Arc::new(SpinLock::new(TestWire::new()));
        let a = Self {
            inner: Arc::new(SpinLock::new(TestWireEndpoint::new(wire.clone(), Side::A))),
        };
        let b = Self {
            inner: Arc::new(SpinLock::new(TestWireEndpoint::new(wire, Side::B))),
        };
        (a, b)
    }

    fn lock(&self) -> crate::util::spinlock::SpinLockGuard<'_, TestWireEndpoint> {
        self.inner.lock()
    }
}

#[cfg(test)]
impl Device for TestNetworkDevice {
    fn name(&self) -> &str {
        "test-net"
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Network
    }
}

#[cfg(test)]
impl NetworkDevice for TestNetworkDevice {
    type Error = ();

    fn mac_address(&self) -> [u8; 6] {
        self.lock().mac
    }

    fn mtu(&self) -> usize {
        1500
    }

    fn link_state(&self) -> LinkState {
        LinkState::Up
    }

    fn transmit_frame(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
        self.lock().transmit(frame);
        Ok(())
    }

    fn receive_frame(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, Self::Error> {
        Ok(self.lock().receive(buffer))
    }
}

#[cfg(test)]
struct TestWire {
    a_to_b: alloc::collections::VecDeque<alloc::vec::Vec<u8>>,
    b_to_a: alloc::collections::VecDeque<alloc::vec::Vec<u8>>,
}

#[cfg(test)]
impl TestWire {
    fn new() -> Self {
        Self {
            a_to_b: alloc::collections::VecDeque::new(),
            b_to_a: alloc::collections::VecDeque::new(),
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum Side {
    A,
    B,
}

#[cfg(test)]
struct TestWireEndpoint {
    wire: Arc<SpinLock<TestWire>>,
    side: Side,
    mac: [u8; 6],
}

#[cfg(test)]
impl TestWireEndpoint {
    fn new(wire: Arc<SpinLock<TestWire>>, side: Side) -> Self {
        let mac = match side {
            Side::A => [0x02, 0x00, 0x00, 0x00, 0x00, 0x0A],
            Side::B => [0x02, 0x00, 0x00, 0x00, 0x00, 0x0B],
        };
        Self { wire, side, mac }
    }

    fn transmit(&mut self, frame: &[u8]) {
        let mut wire = self.wire.lock();
        match self.side {
            Side::A => wire.a_to_b.push_back(frame.to_vec()),
            Side::B => wire.b_to_a.push_back(frame.to_vec()),
        }
    }

    fn receive(&mut self, buffer: &mut [u8]) -> Option<usize> {
        let mut wire = self.wire.lock();
        let frame = match self.side {
            Side::A => wire.b_to_a.pop_front(),
            Side::B => wire.a_to_b.pop_front(),
        }?;
        let len = frame.len().min(buffer.len());
        buffer[..len].copy_from_slice(&frame[..len]);
        Some(len)
    }
}
