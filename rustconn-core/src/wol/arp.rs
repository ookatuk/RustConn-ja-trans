//! ARP-cache lookup for auto-detecting a host's MAC address.
//!
//! Used by the "Get MAC" action in the connection editor to fill the
//! Wake-on-LAN field without the user hunting for the address by hand. This
//! reads the kernel's ARP cache (`/proc/net/arp` on Linux), which only knows a
//! machine that is currently reachable on the same local network segment — a
//! host behind a router shows the router's MAC, not its own, and an offline
//! host is absent entirely. Those limits are the caller's to surface; this
//! module just parses what the kernel already knows.
//!
//! It never sends anything on the network. It only reads a cache the kernel
//! populated as a side effect of ordinary traffic, so a host that has not been
//! contacted recently may be missing even when it is up — a caller that wants a
//! fresh answer should provoke traffic (a ping or a port probe) first.

use std::net::{IpAddr, ToSocketAddrs};

use super::MacAddress;

/// Where the Linux kernel exposes its ARP cache.
#[cfg(target_os = "linux")]
const PROC_NET_ARP: &str = "/proc/net/arp";

/// Looks up the MAC address of `ip` in the local ARP cache.
///
/// Returns `Some(mac)` when the kernel currently has an ARP entry with a valid
/// hardware address for `ip`, `None` otherwise (no entry, an incomplete entry,
/// or a platform without `/proc/net/arp`).
///
/// Only Linux is supported; every other target returns `None` because the ARP
/// cache is read from `/proc/net/arp`, which is Linux-specific.
#[must_use]
pub fn lookup_mac(ip: IpAddr) -> Option<MacAddress> {
    #[cfg(target_os = "linux")]
    {
        let contents = std::fs::read_to_string(PROC_NET_ARP).ok()?;
        parse_arp_table(&contents, ip)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = ip;
        None
    }
}

/// Looks up the MAC address for a host given as an IP or a hostname.
///
/// A hostname is resolved to its IP addresses and each is tried against the ARP
/// cache; the first that has an entry wins. Resolution is local only — this
/// still cannot see a host beyond a router, and returns `None` when the name
/// does not resolve, none of its addresses are in the cache, or the platform is
/// not Linux.
#[must_use]
pub fn lookup_mac_for_host(host: &str) -> Option<MacAddress> {
    let host = host.trim();
    if host.is_empty() {
        return None;
    }

    // A literal IP needs no resolution.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return lookup_mac(ip);
    }

    // Otherwise resolve the hostname. `to_socket_addrs` needs a port; the value
    // is irrelevant since only the IP is used.
    let addrs = (host, 0u16).to_socket_addrs().ok()?;
    for addr in addrs {
        if let Some(mac) = lookup_mac(addr.ip()) {
            return Some(mac);
        }
    }
    None
}

/// Parses a `/proc/net/arp` table and returns the MAC for `target`.
///
/// The file is a fixed-column text table with a header line:
///
/// ```text
/// IP address       HW type     Flags       HW address            Mask     Device
/// 192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
/// ```
///
/// An entry whose hardware address is all zeros (`00:00:00:00:00:00`) is an
/// incomplete resolution and is skipped, as is the header row. The first column
/// is the IP and the fourth is the MAC.
///
/// Only `lookup_mac`'s Linux branch calls this, so on every other target it is
/// dead code in the shipping build — but the test module below exercises it on
/// all platforms. `cfg(any(target_os = "linux", test))` keeps it compiled where
/// it is actually used (the Linux runtime path and every test build) without a
/// blanket `#[allow(dead_code)]` that would also hide a real unused-fn slip.
#[cfg(any(target_os = "linux", test))]
#[must_use]
fn parse_arp_table(contents: &str, target: IpAddr) -> Option<MacAddress> {
    for line in contents.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let ip_col = cols.next()?;
        // HW type, Flags — skipped; the MAC is the fourth column.
        let mac_col = cols.nth(2)?;

        let Ok(entry_ip) = ip_col.parse::<IpAddr>() else {
            continue;
        };
        if entry_ip != target {
            continue;
        }

        let Ok(mac) = MacAddress::parse(mac_col) else {
            continue;
        };
        // A zero MAC is an incomplete/unresolved entry, not a real address.
        if mac.bytes() == &[0u8; 6] {
            continue;
        }
        return Some(mac);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.50     0x1         0x2         00:11:22:33:44:55     *        eth0
192.168.1.99     0x1         0x0         00:00:00:00:00:00     *        eth0
";

    #[test]
    fn finds_a_present_host() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let mac = parse_arp_table(SAMPLE, ip).unwrap();
        assert_eq!(mac.bytes(), &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn finds_a_second_host() {
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        let mac = parse_arp_table(SAMPLE, ip).unwrap();
        assert_eq!(mac.bytes(), &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn absent_host_returns_none() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(parse_arp_table(SAMPLE, ip).is_none());
    }

    #[test]
    fn incomplete_zero_entry_is_skipped() {
        // 192.168.1.99 has an all-zero (unresolved) MAC — must not be returned.
        let ip: IpAddr = "192.168.1.99".parse().unwrap();
        assert!(parse_arp_table(SAMPLE, ip).is_none());
    }

    #[test]
    fn empty_table_returns_none() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(parse_arp_table("", ip).is_none());
        assert!(parse_arp_table("IP address  HW type\n", ip).is_none());
    }

    #[test]
    fn locally_administered_bit_is_detected() {
        // 0x02 (locally administered) set on the first octet.
        let random = MacAddress::parse("02:11:22:33:44:55").unwrap();
        assert!(random.is_locally_administered());
        // A universally administered address does not have the bit.
        let real = MacAddress::parse("a4:83:e7:00:11:22").unwrap();
        assert!(!real.is_locally_administered());
    }
}
