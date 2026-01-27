pub mod smoltcp;

pub use no_std_net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

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
