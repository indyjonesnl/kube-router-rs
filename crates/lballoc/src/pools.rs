//! LoadBalancer IP pool allocation, mirroring `ipRanges` in `lballoc.go`.
//!
//! Addresses are handed out by byte-wise increment across one or more CIDR
//! ranges (per IP family), wrapping to the next range — and eventually back to
//! the first — so allocation is stable and exhaustion is detectable.

use std::net::IpAddr;

use ipnet::IpNet;

/// A cursor over one family's LoadBalancer IP ranges.
#[derive(Debug, Clone)]
pub struct IpRanges {
    ranges: Vec<IpNet>,
    range_index: usize,
    current_ip: Option<IpAddr>,
}

/// Increment an IP address by one, byte-wise with carry (10.0.0.255 → 10.0.1.0).
fn inc_ip(ip: IpAddr) -> IpAddr {
    fn bump(octets: &mut [u8]) {
        for b in octets.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break; // no carry out of this byte
            }
        }
    }
    match ip {
        IpAddr::V4(a) => {
            let mut o = a.octets();
            bump(&mut o);
            IpAddr::V4(o.into())
        }
        IpAddr::V6(a) => {
            let mut o = a.octets();
            bump(&mut o);
            IpAddr::V6(o.into())
        }
    }
}

impl IpRanges {
    /// Build a cursor starting at the first address of the first range.
    pub fn new(ranges: Vec<IpNet>) -> Self {
        let current_ip = ranges.first().map(|r| r.network());
        Self {
            ranges,
            range_index: 0,
            current_ip,
        }
    }

    /// Number of configured ranges (0 means this family is disabled).
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// Whether no ranges are configured.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Whether any range contains `ip`.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.ranges.iter().any(|r| r.contains(&ip))
    }

    /// Advance the cursor one address, wrapping to the next range's first
    /// address (and from the last range back to the first). Mirrors `inc`.
    fn inc(&mut self) {
        let Some(cur) = self.current_ip else {
            return;
        };
        let next = inc_ip(cur);
        let in_range = self.ranges[self.range_index].contains(&next);
        if in_range {
            self.current_ip = Some(next);
        } else {
            self.range_index = if self.range_index + 1 >= self.ranges.len() {
                0
            } else {
                self.range_index + 1
            };
            self.current_ip = Some(self.ranges[self.range_index].network());
        }
    }

    /// Next address not already in `allocated`, scanning from the cursor and
    /// wrapping once. `None` if no ranges are configured or all are allocated.
    pub fn next_free_ip(&mut self, allocated: &[IpAddr]) -> Option<IpAddr> {
        let start = self.current_ip?;
        let mut ip = start;
        loop {
            if !allocated.contains(&ip) {
                return Some(ip);
            }
            self.inc();
            ip = self.current_ip?;
            if ip == start {
                return None; // wrapped all the way around
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn increments_byte_wise_with_carry() {
        assert_eq!(inc_ip(ip("10.0.0.3")), ip("10.0.0.4"));
        assert_eq!(inc_ip(ip("10.0.0.255")), ip("10.0.1.0"));
        assert_eq!(inc_ip(ip("fd00::ff")), ip("fd00::100"));
    }

    #[test]
    fn allocates_sequentially_skipping_allocated() {
        let mut r = IpRanges::new(vec![net("10.0.0.0/29")]);
        // .0 is the network addr; upstream starts there and hands it out.
        assert_eq!(r.next_free_ip(&[]), Some(ip("10.0.0.0")));
        let allocated = vec![ip("10.0.0.0"), ip("10.0.0.1")];
        assert_eq!(r.next_free_ip(&allocated), Some(ip("10.0.0.2")));
    }

    #[test]
    fn wraps_across_multiple_ranges() {
        let mut r = IpRanges::new(vec![net("10.0.0.0/31"), net("10.0.1.0/31")]);
        // /31 → two addresses each. Exhaust the first range's two, cross over.
        let allocated = vec![ip("10.0.0.0"), ip("10.0.0.1")];
        assert_eq!(r.next_free_ip(&allocated), Some(ip("10.0.1.0")));
    }

    #[test]
    fn reports_exhaustion() {
        let mut r = IpRanges::new(vec![net("10.0.0.0/31")]);
        let allocated = vec![ip("10.0.0.0"), ip("10.0.0.1")];
        assert_eq!(r.next_free_ip(&allocated), None);
    }

    #[test]
    fn empty_ranges_allocate_nothing() {
        let mut r = IpRanges::new(vec![]);
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert_eq!(r.next_free_ip(&[]), None);
        assert!(!r.contains(ip("10.0.0.1")));
    }

    #[test]
    fn contains_checks_membership() {
        let r = IpRanges::new(vec![net("203.0.113.0/24")]);
        assert!(r.contains(ip("203.0.113.50")));
        assert!(!r.contains(ip("198.51.100.1")));
    }
}
