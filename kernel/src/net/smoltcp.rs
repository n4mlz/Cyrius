use alloc::vec::Vec;

use smoltcp::iface::{Config, Context, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::wire::{
    EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address,
};

use crate::device::net::NetworkDevice;
use crate::interrupt::SYSTEM_TIMER;
use crate::net::{IpAddr, Ipv4Addr, NetCidr};

const ETHERNET_HEADER_LEN: usize = 14;

/// smoltcp adapter for Cyrius network devices.
///
/// # Note
///
/// This adapter assumes the caller polls the device; the underlying virtio-net driver
/// currently uses polling-only completion waits.
pub struct SmoltcpDevice<D: NetworkDevice> {
    device: D,
    rx_buffer: Vec<u8>,
    tx_buffer: Vec<u8>,
}

impl<D: NetworkDevice> SmoltcpDevice<D> {
    pub fn new(device: D) -> Self {
        let frame_len = device.mtu().saturating_add(ETHERNET_HEADER_LEN);
        let mut rx_buffer = Vec::new();
        rx_buffer.resize(frame_len, 0);
        let mut tx_buffer = Vec::new();
        tx_buffer.resize(frame_len, 0);
        Self {
            device,
            rx_buffer,
            tx_buffer,
        }
    }

    pub fn device(&self) -> &D {
        &self.device
    }

    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    pub fn into_inner(self) -> D {
        self.device
    }
}

pub struct SmoltcpStack<D: NetworkDevice> {
    device: SmoltcpDevice<D>,
    iface: Interface,
    sockets: SocketSet<'static>,
}

impl<D: NetworkDevice> SmoltcpStack<D> {
    /// Build a smoltcp stack for the provided device.
    ///
    /// # Note
    ///
    /// The current configuration enables IPv4 only; IPv6 CIDRs are skipped.
    pub fn new(device: D, ip_addrs: &[NetCidr]) -> Self {
        let mac = device.mac_address();
        let mut device = SmoltcpDevice::new(device);
        let hardware_addr = HardwareAddress::Ethernet(EthernetAddress::from_bytes(&mac));
        let mut config = Config::new(hardware_addr);
        config.random_seed = SYSTEM_TIMER.observed_ticks();

        let now = now();
        let mut iface = Interface::new(config, &mut device, now);
        iface.update_ip_addrs(|addrs| {
            for addr in ip_addrs {
                if let Some(cidr) = to_smoltcp_cidr(*addr) {
                    let _ = addrs.push(cidr);
                } else {
                    crate::println!("[net] skipping unsupported IP family: {addr:?}");
                }
            }
        });

        let sockets = SocketSet::new(Vec::new());
        Self {
            device,
            iface,
            sockets,
        }
    }

    /// Poll the smoltcp stack.
    ///
    /// # Note
    ///
    /// This method must be called by the scheduler or a periodic task; it does not rely
    /// on interrupts for progress.
    pub fn poll(&mut self) -> smoltcp::iface::PollResult {
        self.iface.poll(now(), &mut self.device, &mut self.sockets)
    }

    pub fn interface_mut(&mut self) -> &mut Interface {
        &mut self.iface
    }

    pub fn sockets_mut(&mut self) -> &mut SocketSet<'static> {
        &mut self.sockets
    }

    pub fn with_context_and_sockets<R>(
        &mut self,
        f: impl FnOnce(&mut Context, &mut SocketSet<'static>) -> R,
    ) -> R {
        let iface = &mut self.iface;
        let sockets = &mut self.sockets;
        let mut cx = iface.context();
        f(&mut cx, sockets)
    }

    pub fn device(&self) -> &SmoltcpDevice<D> {
        &self.device
    }

    pub fn device_mut(&mut self) -> &mut SmoltcpDevice<D> {
        &mut self.device
    }
}

fn now() -> Instant {
    let ticks = SYSTEM_TIMER.observed_ticks();
    let millis = if ticks > i64::MAX as u64 {
        i64::MAX
    } else {
        ticks as i64
    };
    // Assumes a monotonic tick source; current implementation treats ticks as milliseconds.
    Instant::from_millis(millis)
}

fn to_smoltcp_cidr(cidr: NetCidr) -> Option<IpCidr> {
    let addr = to_smoltcp_ip(cidr.addr())?;
    Some(IpCidr::new(addr, cidr.prefix()))
}

pub(crate) fn to_smoltcp_ip(addr: IpAddr) -> Option<IpAddress> {
    match addr {
        IpAddr::V4(addr) => Some(IpAddress::Ipv4(to_smoltcp_ipv4(addr))),
        IpAddr::V6(_) => None,
    }
}

pub(crate) fn to_smoltcp_ipv4(addr: Ipv4Addr) -> Ipv4Address {
    let octets = addr.octets();
    Ipv4Address::new(octets[0], octets[1], octets[2], octets[3])
}

pub(crate) fn to_smoltcp_endpoint(addr: crate::net::SocketAddr) -> Option<IpEndpoint> {
    let ip = to_smoltcp_ip(addr.ip())?;
    Some(IpEndpoint::new(ip, addr.port()))
}

#[allow(unreachable_patterns)]
pub(crate) fn to_no_std_ip(addr: IpAddress) -> Option<IpAddr> {
    match addr {
        IpAddress::Ipv4(addr) => {
            let octets = addr.octets();
            Some(IpAddr::V4(Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            )))
        }
        _ => None,
    }
}

pub(crate) fn to_no_std_endpoint(endpoint: IpEndpoint) -> Option<crate::net::SocketAddr> {
    let ip = to_no_std_ip(endpoint.addr)?;
    Some(crate::net::SocketAddr::new(ip, endpoint.port))
}


pub struct SmoltcpRxToken<'a> {
    buffer: &'a [u8],
}

impl<'a> RxToken for SmoltcpRxToken<'a> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.buffer)
    }
}

pub struct SmoltcpTxToken<'a, D: NetworkDevice> {
    device: &'a mut D,
    buffer: &'a mut [u8],
}

impl<'a, D: NetworkDevice> TxToken for SmoltcpTxToken<'a, D> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let len = len.min(self.buffer.len());
        let result = f(&mut self.buffer[..len]);
        if let Err(err) = self.device.transmit_frame(&self.buffer[..len]) {
            crate::println!("[net] smoltcp tx dropped: {err:?}");
        }
        result
    }
}

impl<D: NetworkDevice> Device for SmoltcpDevice<D> {
    type RxToken<'a> = SmoltcpRxToken<'a> where D: 'a;
    type TxToken<'a> = SmoltcpTxToken<'a, D> where D: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame_len = match self.device.receive_frame(&mut self.rx_buffer) {
            Ok(Some(len)) => len,
            Ok(None) => return None,
            Err(err) => {
                crate::println!("[net] smoltcp rx error: {err:?}");
                return None;
            }
        };

        let rx = SmoltcpRxToken {
            buffer: &self.rx_buffer[..frame_len],
        };
        let tx = SmoltcpTxToken {
            device: &mut self.device,
            buffer: &mut self.tx_buffer,
        };
        Some((rx, tx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(SmoltcpTxToken {
            device: &mut self.device,
            buffer: &mut self.tx_buffer,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.device.mtu();
        caps.medium = Medium::Ethernet;
        caps
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use smoltcp::phy::{Device as SmoltcpPhyDevice, RxToken, TxToken};
    use smoltcp::time::Instant;

    use crate::println;
    use crate::test::kernel_test_case;
    use crate::device::net::{LinkState, NetworkDevice};

    use super::{SmoltcpDevice, SmoltcpStack};
    use crate::net::{IpAddr, Ipv4Addr, NetCidr};

    #[kernel_test_case]
    fn smoltcp_device_rx_tx() {
        println!("[test] smoltcp_device_rx_tx");

        let mut device = TestDevice::new();
        device.queue_rx(vec![0xAAu8; 32]);

        let mut smol = SmoltcpDevice::new(device);
        let (rx, mut tx) =
            SmoltcpPhyDevice::receive(&mut smol, Instant::from_millis(0)).expect("rx token");

        let payload = rx.consume(|data| data.to_vec());
        assert_eq!(payload.len(), 32);
        assert!(payload.iter().all(|byte| *byte == 0xAA));

        tx.consume(16, |buf| {
            buf.fill(0x55);
        });

        let inner = smol.into_inner();
        assert_eq!(inner.tx_frames.len(), 1);
        assert_eq!(inner.tx_frames[0], vec![0x55u8; 16]);
    }

    #[kernel_test_case]
    fn smoltcp_stack_poll_smoke() {
        println!("[test] smoltcp_stack_poll_smoke");

        let device = TestDevice::new();
        let addr = NetCidr::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)),
            24,
        );
        let mut stack = SmoltcpStack::new(device, &[addr]);
        let _ = stack.poll();
    }

    /// Validates smoltcp can bind to the QEMU-backed virtio-net device.
    ///
    /// # Implicit dependency
    /// Relies on `xtask::run_qemu` attaching a `virtio-net-pci` device with user networking
    /// during `cargo xtask test`.
    #[kernel_test_case]
    fn smoltcp_stack_virtio_integration() {
        println!("[test] smoltcp_stack_virtio_integration");

        crate::device::virtio::net::with_devices(|devices| {
            assert!(
                !devices.is_empty(),
                "smoltcp integration test requires a network device"
            );
            let shared = crate::device::net::SharedNetworkDevice::from_arc(devices[0].clone());
            let addr = NetCidr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)),
                24,
            );
            let mut stack = SmoltcpStack::new(shared, &[addr]);
            let _ = stack.poll();
        });
    }

    struct TestDevice {
        tx_frames: Vec<Vec<u8>>,
        rx_frames: Vec<Vec<u8>>,
    }

    impl TestDevice {
        fn new() -> Self {
            Self {
                tx_frames: Vec::new(),
                rx_frames: Vec::new(),
            }
        }

        fn queue_rx(&mut self, frame: Vec<u8>) {
            self.rx_frames.push(frame);
        }
    }

    impl crate::device::Device for TestDevice {
        fn name(&self) -> &str {
            "test-net"
        }

        fn device_type(&self) -> crate::device::DeviceType {
            crate::device::DeviceType::Network
        }
    }

    impl NetworkDevice for TestDevice {
        type Error = ();

        fn mac_address(&self) -> [u8; 6] {
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]
        }

        fn mtu(&self) -> usize {
            1500
        }

        fn link_state(&self) -> LinkState {
            LinkState::Up
        }

        fn transmit_frame(&mut self, frame: &[u8]) -> Result<(), Self::Error> {
            self.tx_frames.push(frame.to_vec());
            Ok(())
        }

        fn receive_frame(&mut self, buffer: &mut [u8]) -> Result<Option<usize>, Self::Error> {
            let Some(frame) = self.rx_frames.pop() else {
                return Ok(None);
            };
            let len = frame.len().min(buffer.len());
            buffer[..len].copy_from_slice(&frame[..len]);
            Ok(Some(len))
        }
    }
}
