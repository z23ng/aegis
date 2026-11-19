use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::RawFd;

const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
const SIOCSIFFLAGS: libc::c_ulong = 0x8914;

/// Bring up the loopback interface (`lo`) inside the current network namespace.
pub fn bring_up_loopback() -> io::Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }

    let res = unsafe {
        let mut ifr: libc::ifreq = mem::zeroed();
        ifr.ifr_name[0] = b'l' as libc::c_char;
        ifr.ifr_name[1] = b'o' as libc::c_char;
        ifr.ifr_name[2] = 0;

        if libc::ioctl(sock, SIOCGIFFLAGS as _, &mut ifr) != 0 {
            Err(io::Error::last_os_error())
        } else {
            ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            if libc::ioctl(sock, SIOCSIFFLAGS as _, &mut ifr) != 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    };

    unsafe {
        libc::close(sock);
    }
    res
}

/// Bind a TCP listening socket on `127.0.0.1:<port>` in the current network namespace.
/// Returns `(raw_fd, bound_port)`.
pub fn bind_in_netns_tcp_listener(port: u16) -> io::Result<(RawFd, u16)> {
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let opt: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            (&opt as *const libc::c_int).cast(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    addr.sin_family = libc::AF_INET as libc::sa_family_t;
    addr.sin_port = port.to_be();
    addr.sin_addr = libc::in_addr {
        s_addr: u32::from(Ipv4Addr::LOCALHOST).to_be(),
    };

    let addr_len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    if unsafe { libc::bind(fd, (&addr as *const libc::sockaddr_in).cast(), addr_len) } != 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    if unsafe { libc::listen(fd, 128) } != 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    let mut bound: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut bound_len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            fd,
            (&mut bound as *mut libc::sockaddr_in).cast(),
            &mut bound_len,
        )
    } != 0
    {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    Ok((fd, u16::from_be(bound.sin_port)))
}

/// Send an open file descriptor (plus a `u16` port tag) over an `AF_UNIX` socket using `SCM_RIGHTS`.
pub fn send_fd(unix_sock: RawFd, fd_to_send: RawFd, port_tag: u16) -> io::Result<()> {
    let mut data = port_tag.to_be_bytes();
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };

    let cmsg_space = unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_space as _;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            (&fd_to_send as *const RawFd).cast::<u8>(),
            libc::CMSG_DATA(cmsg),
            mem::size_of::<RawFd>(),
        );
    }

    let n = unsafe { libc::sendmsg(unix_sock, &msg, 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Receive a file descriptor (plus its `u16` port tag) sent via `SCM_RIGHTS`.
pub fn recv_fd(unix_sock: RawFd) -> io::Result<(RawFd, u16)> {
    let mut data = [0u8; 2];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };

    let cmsg_space = unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast();
    msg.msg_controllen = cmsg_space as _;

    let n = unsafe { libc::recvmsg(unix_sock, &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n == 0 {
        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
    }

    let port_tag = u16::from_be_bytes(data);
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SCM_RIGHTS {
                let mut received_fd: RawFd = -1;
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(cmsg),
                    (&mut received_fd as *mut RawFd).cast::<u8>(),
                    mem::size_of::<RawFd>(),
                );
                return Ok((received_fd, port_tag));
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "missing SCM_RIGHTS control message",
    ))
}

/// Parse an IPv4 or bracketed/unbracketed IPv6 literal.
pub fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    let trimmed = host.trim().trim_start_matches('[').trim_end_matches(']');
    trimmed.parse::<IpAddr>().ok()
}

/// Returns `true` if `ip` points to a cloud metadata endpoint, link-local address,
/// loopback, multicast, unspecified address, or (when `block_private_cidrs` is true)
/// any RFC1918 / RFC6598 / ULA private range.
pub fn is_forbidden_ip(ip: IpAddr, block_private_cidrs: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_ipv4(v4, block_private_cidrs),
        IpAddr::V6(v6) => is_forbidden_ipv6(v6, block_private_cidrs),
    }
}

fn is_forbidden_ipv4(v4: Ipv4Addr, block_private_cidrs: bool) -> bool {
    let octets = v4.octets();
    // Always block link-local / cloud metadata (169.254.0.0/16, including 169.254.169.254),
    // "this network" (0.0.0.0/8), multicast (224.0.0.0/4), and broadcast (255.255.255.255).
    if v4.is_link_local()
        || octets[0] == 0
        || v4.is_multicast()
        || v4.is_broadcast()
        || octets[0] >= 240
    {
        return true;
    }

    if !block_private_cidrs {
        return false;
    }

    // Loopback 127.0.0.0/8
    if v4.is_loopback() {
        return true;
    }
    // RFC1918 private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    if v4.is_private() {
        return true;
    }
    // CGNAT 100.64.0.0/10
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return true;
    }
    // Documentation / benchmarking / protocol assignments
    if (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
    {
        return true;
    }
    false
}

fn is_forbidden_ipv6(v6: Ipv6Addr, block_private_cidrs: bool) -> bool {
    if let Some(mapped_v4) = v6.to_ipv4_mapped() {
        return is_forbidden_ipv4(mapped_v4, block_private_cidrs);
    }
    let segs = v6.segments();
    // Always block unspecified (::), link-local (fe80::/10), multicast (ff00::/8)
    if v6.is_unspecified() || (segs[0] & 0xffc0) == 0xfe80 || v6.is_multicast() {
        return true;
    }
    if !block_private_cidrs {
        return false;
    }
    // Loopback (::1) and Unique Local Addresses (fc00::/7)
    v6.is_loopback() || (segs[0] & 0xfe00) == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::os::fd::AsRawFd;

    #[test]
    fn forbidden_ip_blocks_metadata_loopback_and_rfc1918() {
        // Metadata & link-local always blocked even if block_private_cidrs=false
        assert!(is_forbidden_ip("169.254.169.254".parse().unwrap(), false));
        assert!(is_forbidden_ip("169.254.169.254".parse().unwrap(), true));
        assert!(is_forbidden_ip("0.0.0.0".parse().unwrap(), true));

        // Private & loopback blocked when block_private_cidrs=true
        assert!(is_forbidden_ip("127.0.0.1".parse().unwrap(), true));
        assert!(is_forbidden_ip("10.0.0.5".parse().unwrap(), true));
        assert!(is_forbidden_ip("172.16.10.2".parse().unwrap(), true));
        assert!(is_forbidden_ip("192.168.1.1".parse().unwrap(), true));
        assert!(is_forbidden_ip("100.64.0.1".parse().unwrap(), true));
        assert!(is_forbidden_ip("::1".parse().unwrap(), true));
        assert!(is_forbidden_ip("fd00::1".parse().unwrap(), true));
        assert!(is_forbidden_ip("::ffff:169.254.169.254".parse().unwrap(), true));
        assert!(is_forbidden_ip("::ffff:10.0.0.1".parse().unwrap(), true));

        // Public IPs are allowed by IP filter
        assert!(!is_forbidden_ip("93.184.216.34".parse().unwrap(), true));
        assert!(!is_forbidden_ip("140.82.121.6".parse().unwrap(), true));
        assert!(!is_forbidden_ip("2606:4700:4700::1111".parse().unwrap(), true));
    }

    #[test]
    fn scm_rights_fd_passing_round_trip() {
        let (a, b) = UnixStream::pair().expect("socketpair");
        let (listener_fd, port) = bind_in_netns_tcp_listener(0).expect("bind localhost");
        assert!(port > 0);
        send_fd(a.as_raw_fd(), listener_fd, port).expect("send_fd");
        unsafe { libc::close(listener_fd) };

        let (received_fd, tag) = recv_fd(b.as_raw_fd()).expect("recv_fd");
        assert!(received_fd >= 0);
        assert_eq!(tag, port);
        unsafe { libc::close(received_fd) };
    }
}
