use crate::net::{IpAddr, Ipv4Addr, NetCidr};

/// Default IPv4 configuration for QEMU user networking.
///
/// # Implicit dependency
/// Assumes QEMU `-netdev user` where the guest address is `10.0.2.15/24`
/// and the default gateway is `10.0.2.2`.
pub const DEFAULT_IPV4: NetCidr = NetCidr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 24);
pub const DEFAULT_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
