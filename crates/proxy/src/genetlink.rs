//! Genetlink (native netlink) IPVS backend, mirroring the encoding in
//! `github.com/moby/ipvs` (kube-router's upstream IPVS library).
//!
//! Talks to the kernel `IPVS` generic-netlink family directly — no `ipvsadm`
//! process per operation. Used behind [`crate::ipvs::SystemIpvs`], which falls
//! back to the `ipvsadm` binary if genetlink is unavailable or errors, so a
//! kernel/permission problem degrades gracefully rather than failing the sync.

use std::io;
use std::net::IpAddr;

use crate::ipvs::{IpvsDestination, IpvsService};
use crate::model::{Protocol, Scheduler};

// Generic netlink / control-family constants.
const NETLINK_GENERIC: i32 = 16;
const GENL_ID_CTRL: u16 = 0x10;
const CTRL_CMD_GETFAMILY: u8 = 3;
const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;

// nlmsg flags.
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLMSG_ERROR: u16 = 0x02;

// IPVS genl commands (moby/ipvs constants order).
const IPVS_CMD_NEW_SERVICE: u8 = 1;
const IPVS_CMD_DEL_SERVICE: u8 = 3;
const IPVS_CMD_NEW_DEST: u8 = 5;
const IPVS_CMD_DEL_DEST: u8 = 7;

// Top-level command attributes.
const IPVS_CMD_ATTR_SERVICE: u16 = 1;
const IPVS_CMD_ATTR_DEST: u16 = 2;

// Service nested attributes.
const SVC_ATTR_AF: u16 = 1;
const SVC_ATTR_PROTOCOL: u16 = 2;
const SVC_ATTR_ADDRESS: u16 = 3;
const SVC_ATTR_PORT: u16 = 4;
const SVC_ATTR_FWMARK: u16 = 5;
const SVC_ATTR_SCHED_NAME: u16 = 6;
const SVC_ATTR_FLAGS: u16 = 7;
const SVC_ATTR_TIMEOUT: u16 = 8;
const SVC_ATTR_NETMASK: u16 = 9;

// Destination nested attributes.
const DEST_ATTR_ADDRESS: u16 = 1;
const DEST_ATTR_PORT: u16 = 2;
const DEST_ATTR_FWD_METHOD: u16 = 3;
const DEST_ATTR_WEIGHT: u16 = 4;

// Forwarding methods + service flags.
const FWD_MASQ: u32 = 0;
const FWD_TUNNEL: u32 = 2;
const SVC_F_PERSISTENT: u32 = 0x0001;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

fn proto_num(p: Protocol) -> u16 {
    match p {
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
        Protocol::Sctp => 132,
    }
}

fn addr_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

fn af(ip: IpAddr) -> u16 {
    if ip.is_ipv6() {
        AF_INET6
    } else {
        AF_INET
    }
}

/// Encode a netlink attribute (TLV, 4-byte aligned). `nested` sets the N flag.
fn nla(attr_type: u16, payload: &[u8]) -> Vec<u8> {
    let total = 4 + payload.len();
    let mut out = Vec::with_capacity((total + 3) & !3);
    out.extend_from_slice(&(total as u16).to_ne_bytes());
    out.extend_from_slice(&attr_type.to_ne_bytes());
    out.extend_from_slice(payload);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

fn nla_u16(t: u16, v: u16) -> Vec<u8> {
    nla(t, &v.to_ne_bytes())
}
fn nla_u32(t: u16, v: u32) -> Vec<u8> {
    nla(t, &v.to_ne_bytes())
}
fn zero_terminated(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

/// Build the nested `IPVS_CMD_ATTR_SERVICE` payload for a virtual service.
fn service_attr(svc: &IpvsService) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(nla_u16(SVC_ATTR_AF, af(svc.addr)));
    b.extend(nla_u16(SVC_ATTR_PROTOCOL, proto_num(svc.protocol)));
    b.extend(nla(SVC_ATTR_ADDRESS, &addr_bytes(svc.addr)));
    b.extend(nla(SVC_ATTR_PORT, &svc.port.to_be_bytes())); // network byte order
    b.extend(nla(
        SVC_ATTR_SCHED_NAME,
        &zero_terminated(svc.scheduler.ipvs_name()),
    ));
    let flags = if svc.persistent.is_some() {
        SVC_F_PERSISTENT
    } else {
        0
    };
    // Flags attribute is {flags u32, mask u32}.
    let mut fbuf = flags.to_ne_bytes().to_vec();
    fbuf.extend_from_slice(&0xFFFF_FFFFu32.to_ne_bytes());
    b.extend(nla(SVC_ATTR_FLAGS, &fbuf));
    b.extend(nla_u32(SVC_ATTR_TIMEOUT, svc.persistent.unwrap_or(0)));
    let netmask = if svc.addr.is_ipv6() { 128 } else { 0xFFFF_FFFF };
    b.extend(nla_u32(SVC_ATTR_NETMASK, netmask));
    nla(IPVS_CMD_ATTR_SERVICE, &b)
}

/// Build the nested service attr for a FWMARK service (no addr/proto/port).
fn fwmark_service_attr(fwmark: u32, scheduler: Scheduler, persistent: Option<u32>) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(nla_u16(SVC_ATTR_AF, AF_INET));
    b.extend(nla_u32(SVC_ATTR_FWMARK, fwmark));
    b.extend(nla(
        SVC_ATTR_SCHED_NAME,
        &zero_terminated(scheduler.ipvs_name()),
    ));
    let flags = if persistent.is_some() {
        SVC_F_PERSISTENT
    } else {
        0
    };
    let mut fbuf = flags.to_ne_bytes().to_vec();
    fbuf.extend_from_slice(&0xFFFF_FFFFu32.to_ne_bytes());
    b.extend(nla(SVC_ATTR_FLAGS, &fbuf));
    b.extend(nla_u32(SVC_ATTR_TIMEOUT, persistent.unwrap_or(0)));
    b.extend(nla_u32(SVC_ATTR_NETMASK, 0xFFFF_FFFF));
    nla(IPVS_CMD_ATTR_SERVICE, &b)
}

/// Build the nested `IPVS_CMD_ATTR_DEST` payload for a real server.
fn dest_attr(dst: &IpvsDestination) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(nla(DEST_ATTR_ADDRESS, &addr_bytes(dst.addr)));
    b.extend(nla(DEST_ATTR_PORT, &dst.port.to_be_bytes()));
    let fwd = if dst.tunnel { FWD_TUNNEL } else { FWD_MASQ };
    b.extend(nla_u32(DEST_ATTR_FWD_METHOD, fwd));
    b.extend(nla_u32(DEST_ATTR_WEIGHT, dst.weight as u32));
    nla(IPVS_CMD_ATTR_DEST, &b)
}

/// A generic-netlink socket bound for IPVS commands.
pub struct Genl {
    fd: i32,
    seq: u32,
    family: u16,
}

impl Genl {
    /// Open the genl socket and resolve the `IPVS` family id.
    pub fn open() -> io::Result<Self> {
        // SAFETY: standard socket(2) with valid constants.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_GENERIC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: binding the netlink socket with a zeroed sockaddr_nl (auto pid).
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        let mut g = Self {
            fd,
            seq: 0,
            family: 0,
        };
        g.family = g.resolve_family()?;
        Ok(g)
    }

    fn next_seq(&mut self) -> u32 {
        self.seq += 1;
        self.seq
    }

    /// Send one genl message (nlmsg + genlmsghdr + `payload`) and read the ACK.
    fn request(&mut self, family: u16, cmd: u8, payload: &[u8]) -> io::Result<Vec<u8>> {
        let seq = self.next_seq();
        // genlmsghdr: cmd, version=1, reserved u16.
        let mut body = vec![cmd, 1u8, 0, 0];
        body.extend_from_slice(payload);
        let total = 16 + body.len();
        let mut msg = Vec::with_capacity(total);
        msg.extend_from_slice(&(total as u32).to_ne_bytes()); // nlmsg_len
        msg.extend_from_slice(&family.to_ne_bytes()); // nlmsg_type
        msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        msg.extend_from_slice(&seq.to_ne_bytes());
        msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
        msg.extend_from_slice(&body);

        // SAFETY: send the fully-formed message buffer.
        let sent =
            unsafe { libc::send(self.fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u8; 8192];
        // SAFETY: recv into an owned buffer.
        let n = unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        buf.truncate(n as usize);
        // Parse the first nlmsg header; NLMSG_ERROR carries an errno (0 = ACK).
        if buf.len() >= 20 {
            let ntype = u16::from_ne_bytes([buf[4], buf[5]]);
            if ntype == NLMSG_ERROR {
                let err = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
                if err != 0 {
                    return Err(io::Error::from_raw_os_error(-err));
                }
            }
        }
        Ok(buf)
    }

    /// Resolve the numeric family id for `IPVS` via the genl controller.
    fn resolve_family(&mut self) -> io::Result<u16> {
        let payload = nla(CTRL_ATTR_FAMILY_NAME, &zero_terminated("IPVS"));
        let resp = self.request(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, &payload)?;
        // Skip nlmsghdr(16) + genlmsghdr(4); scan attrs for CTRL_ATTR_FAMILY_ID.
        let attrs = resp.get(20..).unwrap_or(&[]);
        let mut i = 0;
        while i + 4 <= attrs.len() {
            let len = u16::from_ne_bytes([attrs[i], attrs[i + 1]]) as usize;
            let t = u16::from_ne_bytes([attrs[i + 2], attrs[i + 3]]);
            if len < 4 || i + len > attrs.len() {
                break;
            }
            if t == CTRL_ATTR_FAMILY_ID && len >= 6 {
                return Ok(u16::from_ne_bytes([attrs[i + 4], attrs[i + 5]]));
            }
            i += (len + 3) & !3;
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "IPVS genl family not found",
        ))
    }

    /// `IPVS_CMD_NEW_SERVICE` for a VIP service.
    pub fn add_service(&mut self, svc: &IpvsService) -> io::Result<()> {
        let p = service_attr(svc);
        self.request(self.family, IPVS_CMD_NEW_SERVICE, &p)
            .map(|_| ())
    }
    /// `IPVS_CMD_DEL_SERVICE`.
    pub fn del_service(&mut self, svc: &IpvsService) -> io::Result<()> {
        let p = service_attr(svc);
        self.request(self.family, IPVS_CMD_DEL_SERVICE, &p)
            .map(|_| ())
    }
    /// `IPVS_CMD_NEW_DEST` under a VIP service.
    pub fn add_destination(&mut self, svc: &IpvsService, dst: &IpvsDestination) -> io::Result<()> {
        let mut p = service_attr(svc);
        p.extend(dest_attr(dst));
        self.request(self.family, IPVS_CMD_NEW_DEST, &p).map(|_| ())
    }
    /// `IPVS_CMD_DEL_DEST`.
    pub fn del_destination(&mut self, svc: &IpvsService, dst: &IpvsDestination) -> io::Result<()> {
        let mut p = service_attr(svc);
        p.extend(dest_attr(dst));
        self.request(self.family, IPVS_CMD_DEL_DEST, &p).map(|_| ())
    }
    /// `IPVS_CMD_NEW_SERVICE` for a FWMARK service (DSR).
    pub fn add_fwmark_service(
        &mut self,
        fwmark: u32,
        scheduler: Scheduler,
        persistent: Option<u32>,
    ) -> io::Result<()> {
        let p = fwmark_service_attr(fwmark, scheduler, persistent);
        self.request(self.family, IPVS_CMD_NEW_SERVICE, &p)
            .map(|_| ())
    }
    /// `IPVS_CMD_NEW_DEST` under a FWMARK service.
    pub fn add_fwmark_destination(&mut self, fwmark: u32, dst: &IpvsDestination) -> io::Result<()> {
        let mut p = fwmark_service_attr(fwmark, Scheduler::Rr, None);
        p.extend(dest_attr(dst));
        self.request(self.family, IPVS_CMD_NEW_DEST, &p).map(|_| ())
    }
}

impl Drop for Genl {
    fn drop(&mut self) {
        // SAFETY: fd is owned and valid for the lifetime of Genl.
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nla_is_4byte_aligned_with_len_and_type() {
        let a = nla(3, &[1, 2, 3]); // 4 hdr + 3 data = 7 → padded to 8
        assert_eq!(a.len(), 8);
        assert_eq!(u16::from_ne_bytes([a[0], a[1]]), 7); // length excludes padding
        assert_eq!(u16::from_ne_bytes([a[2], a[3]]), 3); // type
        assert_eq!(&a[4..7], &[1, 2, 3]);
        assert_eq!(a[7], 0); // pad
    }

    #[test]
    fn service_attr_encodes_family_proto_and_network_order_port() {
        let svc = IpvsService {
            addr: "10.96.0.10".parse().unwrap(),
            protocol: Protocol::Tcp,
            port: 80,
            scheduler: Scheduler::Rr,
            persistent: None,
        };
        let a = service_attr(&svc);
        // Outer attr is the nested SERVICE attr.
        assert_eq!(u16::from_ne_bytes([a[2], a[3]]), IPVS_CMD_ATTR_SERVICE);
        // Port 80 in network order (be) appears as 0x00,0x50 somewhere in the body.
        assert!(a.windows(2).any(|w| w == [0x00, 0x50]));
        // scheduler "rr" NUL-terminated present.
        assert!(a.windows(3).any(|w| w == b"rr\0"));
    }

    #[test]
    fn proto_and_fwd_method_numbers() {
        assert_eq!(proto_num(Protocol::Tcp), 6);
        assert_eq!(proto_num(Protocol::Udp), 17);
        assert_eq!(proto_num(Protocol::Sctp), 132);
        let masq = dest_attr(&IpvsDestination {
            addr: "10.244.0.5".parse().unwrap(),
            port: 8080,
            weight: 1,
            tunnel: false,
        });
        // FWD method u32 = 0 (masq) present.
        assert!(masq.windows(4).any(|w| w == FWD_MASQ.to_ne_bytes()));
        let tun = dest_attr(&IpvsDestination {
            addr: "10.244.0.5".parse().unwrap(),
            port: 8080,
            weight: 1,
            tunnel: true,
        });
        assert!(tun.windows(4).any(|w| w == FWD_TUNNEL.to_ne_bytes()));
    }
}
