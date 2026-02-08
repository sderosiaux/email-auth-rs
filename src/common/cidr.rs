use std::net::{Ipv4Addr, Ipv6Addr};

/// Check if an IPv4 address falls within a network/prefix.
/// prefix=0 matches all. prefix>32 matches none.
pub fn ip4_in_network(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 32 {
        return false;
    }
    let mask = !0u32 << (32 - prefix);
    (u32::from(ip) & mask) == (u32::from(network) & mask)
}

/// Check if an IPv6 address falls within a network/prefix.
/// prefix=0 matches all. prefix>128 matches none.
pub fn ip6_in_network(ip: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix > 128 {
        return false;
    }
    let mask = !0u128 << (128 - prefix);
    (u128::from(ip) & mask) == (u128::from(network) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    // CHK-243: CIDR matching custom implementation

    // --- IPv4 tests ---

    #[test]
    fn ip4_exact_match() {
        let ip: Ipv4Addr = "192.168.1.1".parse().unwrap();
        let net: Ipv4Addr = "192.168.1.1".parse().unwrap();
        assert!(ip4_in_network(ip, net, 32));
    }

    #[test]
    fn ip4_subnet_match() {
        let ip: Ipv4Addr = "192.168.1.100".parse().unwrap();
        let net: Ipv4Addr = "192.168.1.0".parse().unwrap();
        assert!(ip4_in_network(ip, net, 24));
    }

    #[test]
    fn ip4_subnet_no_match() {
        let ip: Ipv4Addr = "192.168.2.1".parse().unwrap();
        let net: Ipv4Addr = "192.168.1.0".parse().unwrap();
        assert!(!ip4_in_network(ip, net, 24));
    }

    #[test]
    fn ip4_prefix_0_matches_all() {
        let ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let net: Ipv4Addr = "192.168.1.0".parse().unwrap();
        assert!(ip4_in_network(ip, net, 0));
    }

    #[test]
    fn ip4_prefix_too_large() {
        let ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        assert!(!ip4_in_network(ip, ip, 33));
    }

    #[test]
    fn ip4_slash_16() {
        let ip: Ipv4Addr = "10.20.99.1".parse().unwrap();
        let net: Ipv4Addr = "10.20.0.0".parse().unwrap();
        assert!(ip4_in_network(ip, net, 16));
    }

    #[test]
    fn ip4_slash_16_boundary() {
        let ip: Ipv4Addr = "10.21.0.0".parse().unwrap();
        let net: Ipv4Addr = "10.20.0.0".parse().unwrap();
        assert!(!ip4_in_network(ip, net, 16));
    }

    // --- IPv6 tests ---

    #[test]
    fn ip6_exact_match() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let net: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(ip6_in_network(ip, net, 128));
    }

    #[test]
    fn ip6_subnet_match() {
        let ip: Ipv6Addr = "2001:db8::abcd".parse().unwrap();
        let net: Ipv6Addr = "2001:db8::".parse().unwrap();
        assert!(ip6_in_network(ip, net, 32));
    }

    #[test]
    fn ip6_subnet_no_match() {
        let ip: Ipv6Addr = "2001:db9::1".parse().unwrap();
        let net: Ipv6Addr = "2001:db8::".parse().unwrap();
        assert!(!ip6_in_network(ip, net, 32));
    }

    #[test]
    fn ip6_prefix_0_matches_all() {
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let net: Ipv6Addr = "2001:db8::".parse().unwrap();
        assert!(ip6_in_network(ip, net, 0));
    }

    #[test]
    fn ip6_prefix_too_large() {
        let ip: Ipv6Addr = "::1".parse().unwrap();
        assert!(!ip6_in_network(ip, ip, 129));
    }

    #[test]
    fn ip6_slash_64() {
        let ip: Ipv6Addr = "2001:db8:0:0:ffff::1".parse().unwrap();
        let net: Ipv6Addr = "2001:db8::".parse().unwrap();
        assert!(ip6_in_network(ip, net, 64));
    }

    #[test]
    fn ip6_slash_64_boundary() {
        let ip: Ipv6Addr = "2001:db8:0:1::1".parse().unwrap();
        let net: Ipv6Addr = "2001:db8::".parse().unwrap();
        assert!(!ip6_in_network(ip, net, 64));
    }
}
