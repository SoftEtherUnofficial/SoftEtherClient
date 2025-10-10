//! Network utilities for SoftEther VPN
//!
//! Blocking I/O socket abstractions matching SoftEther C Network.h/Network.c
//! Uses std::net for FFI compatibility (no async/tokio)

use crate::error::{Error, Result};
use std::io::{Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
    UdpSocket,
};
use std::time::Duration;

/// Socket type constants (matches SoftEther C)
pub const SOCK_TCP: u32 = 1;
pub const SOCK_UDP: u32 = 2;

/// Default connection timeout (30 seconds)
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default socket buffer size
pub const DEFAULT_BUFFER_SIZE: usize = 65536;

/// TCP socket wrapper with SoftEther-compatible API
pub struct TcpSocket {
    stream: TcpStream,
    connected: bool,
    server_mode: bool,
}

impl TcpSocket {
    /// Create a new TCP socket from an existing stream
    fn from_stream(stream: TcpStream, server_mode: bool) -> Result<Self> {
        stream.set_nodelay(true).map_err(|e| {
            Error::Network(format!("Failed to set TCP_NODELAY: {}", e))
        })?;

        Ok(Self {
            stream,
            connected: true,
            server_mode,
        })
    }

    /// Connect to a remote host
    /// Matches SoftEther C: Connect(hostname, port)
    pub fn connect(hostname: &str, port: u16) -> Result<Self> {
        Self::connect_timeout(hostname, port, DEFAULT_TIMEOUT)
    }

    /// Connect with timeout
    /// Matches SoftEther C: ConnectEx(hostname, port, timeout)
    pub fn connect_timeout(hostname: &str, port: u16, timeout: Duration) -> Result<Self> {
        let addr = resolve_hostname(hostname, port)?;

        let stream = TcpStream::connect_timeout(&addr, timeout).map_err(|e| {
            Error::Network(format!("Failed to connect to {}:{}: {}", hostname, port, e))
        })?;

        Self::from_stream(stream, false)
    }

    /// Set read timeout
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.stream
            .set_read_timeout(timeout)
            .map_err(|e| Error::Network(format!("Failed to set read timeout: {}", e)))
    }

    /// Set write timeout
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.stream
            .set_write_timeout(timeout)
            .map_err(|e| Error::Network(format!("Failed to set write timeout: {}", e)))
    }

    /// Set TCP keepalive
    pub fn set_keepalive(&self, keepalive: Option<Duration>) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = self.stream.as_raw_fd();
            unsafe {
                if let Some(_duration) = keepalive {
                    // Enable keepalive
                    let optval: libc::c_int = 1;
                    if libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_KEEPALIVE,
                        &optval as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&optval) as libc::socklen_t,
                    ) != 0
                    {
                        return Err(Error::Network("Failed to set SO_KEEPALIVE".to_string()));
                    }

                    // Set keepalive time (seconds)
                    #[cfg(target_os = "linux")]
                    {
                        let time = duration.as_secs() as libc::c_int;
                        if libc::setsockopt(
                            fd,
                            libc::IPPROTO_TCP,
                            libc::TCP_KEEPIDLE,
                            &time as *const _ as *const libc::c_void,
                            std::mem::size_of_val(&time) as libc::socklen_t,
                        ) != 0
                        {
                            return Err(Error::Network(
                                "Failed to set TCP_KEEPIDLE".to_string(),
                            ));
                        }
                    }
                } else {
                    // Disable keepalive
                    let optval: libc::c_int = 0;
                    if libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_KEEPALIVE,
                        &optval as *const _ as *const libc::c_void,
                        std::mem::size_of_val(&optval) as libc::socklen_t,
                    ) != 0
                    {
                        return Err(Error::Network(
                            "Failed to disable SO_KEEPALIVE".to_string(),
                        ));
                    }
                }
            }
            Ok(())
        }

        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawSocket;
            let socket = self.stream.as_raw_socket();
            unsafe {
                if let Some(duration) = keepalive {
                    let optval: i32 = 1;
                    if winapi::um::winsock2::setsockopt(
                        socket as usize,
                        winapi::um::winsock2::SOL_SOCKET,
                        winapi::um::winsock2::SO_KEEPALIVE,
                        &optval as *const _ as *const i8,
                        std::mem::size_of_val(&optval) as i32,
                    ) != 0
                    {
                        return Err(Error::Network("Failed to set SO_KEEPALIVE".to_string()));
                    }
                } else {
                    let optval: i32 = 0;
                    if winapi::um::winsock2::setsockopt(
                        socket as usize,
                        winapi::um::winsock2::SOL_SOCKET,
                        winapi::um::winsock2::SO_KEEPALIVE,
                        &optval as *const _ as *const i8,
                        std::mem::size_of_val(&optval) as i32,
                    ) != 0
                    {
                        return Err(Error::Network(
                            "Failed to disable SO_KEEPALIVE".to_string(),
                        ));
                    }
                }
            }
            Ok(())
        }

        #[cfg(not(any(unix, windows)))]
        {
            Ok(()) // No-op on unsupported platforms
        }
    }

    /// Read data from socket
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.stream
            .read(buf)
            .map_err(|e| Error::Network(format!("Failed to read from socket: {}", e)))
    }

    /// Write data to socket
    pub fn send(&mut self, buf: &[u8]) -> Result<usize> {
        self.stream
            .write(buf)
            .map_err(|e| Error::Network(format!("Failed to write to socket: {}", e)))
    }

    /// Flush the write buffer
    pub fn flush(&mut self) -> Result<()> {
        self.stream
            .flush()
            .map_err(|e| Error::Network(format!("Failed to flush socket: {}", e)))
    }

    /// Shutdown the socket
    pub fn shutdown(&self, how: Shutdown) -> Result<()> {
        self.stream
            .shutdown(how)
            .map_err(|e| Error::Network(format!("Failed to shutdown socket: {}", e)))
    }

    /// Get local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.stream
            .local_addr()
            .map_err(|e| Error::Network(format!("Failed to get local address: {}", e)))
    }

    /// Get peer address
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.stream
            .peer_addr()
            .map_err(|e| Error::Network(format!("Failed to get peer address: {}", e)))
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Check if server mode
    pub fn is_server_mode(&self) -> bool {
        self.server_mode
    }
}

/// TCP listener wrapper with SoftEther-compatible API
pub struct TcpSocketListener {
    listener: TcpListener,
    _local_only: bool, // Stored for future use (e.g., socket options)
}

impl TcpSocketListener {
    /// Listen on a port (all interfaces)
    /// Matches SoftEther C: Listen(port)
    pub fn listen(port: u16) -> Result<Self> {
        Self::listen_ex(port, false)
    }

    /// Listen with options
    /// Matches SoftEther C: ListenEx(port, local_only)
    pub fn listen_ex(port: u16, local_only: bool) -> Result<Self> {
        let addr = if local_only {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
        };

        let listener = TcpListener::bind(addr)
            .map_err(|e| Error::Network(format!("Failed to bind to port {}: {}", port, e)))?;

        Ok(Self {
            listener,
            _local_only: local_only,
        })
    }

    /// Listen on IPv6
    /// Matches SoftEther C: Listen6(port)
    pub fn listen6(port: u16) -> Result<Self> {
        Self::listen6_ex(port, false)
    }

    /// Listen on IPv6 with options
    /// Matches SoftEther C: ListenEx6(port, local_only)
    pub fn listen6_ex(port: u16, local_only: bool) -> Result<Self> {
        let addr = if local_only {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
        };

        let listener = TcpListener::bind(addr)
            .map_err(|e| Error::Network(format!("Failed to bind to port {}: {}", port, e)))?;

        Ok(Self {
            listener,
            _local_only: local_only,
        })
    }

    /// Accept incoming connection
    /// Matches SoftEther C: Accept(sock)
    pub fn accept(&self) -> Result<TcpSocket> {
        let (stream, _addr) = self
            .listener
            .accept()
            .map_err(|e| Error::Network(format!("Failed to accept connection: {}", e)))?;

        TcpSocket::from_stream(stream, true)
    }

    /// Get local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|e| Error::Network(format!("Failed to get local address: {}", e)))
    }

    /// Set non-blocking mode
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.listener
            .set_nonblocking(nonblocking)
            .map_err(|e| Error::Network(format!("Failed to set non-blocking mode: {}", e)))
    }
}

/// UDP socket wrapper with SoftEther-compatible API
pub struct UdpSocketWrapper {
    socket: UdpSocket,
    connected: bool,
}

impl UdpSocketWrapper {
    /// Create a new UDP socket
    /// Matches SoftEther C: NewUDP(port)
    pub fn new(port: u16) -> Result<Self> {
        Self::new_ex(port, false)
    }

    /// Create a new UDP socket (IPv4 or IPv6)
    /// Matches SoftEther C: NewUDPEx(port, ipv6)
    pub fn new_ex(port: u16, ipv6: bool) -> Result<Self> {
        let addr = if ipv6 {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
        };

        let socket = UdpSocket::bind(addr)
            .map_err(|e| Error::Network(format!("Failed to bind UDP socket: {}", e)))?;

        Ok(Self {
            socket,
            connected: false,
        })
    }

    /// Connect UDP socket to remote address
    pub fn connect(&mut self, hostname: &str, port: u16) -> Result<()> {
        let addr = resolve_hostname(hostname, port)?;

        self.socket
            .connect(addr)
            .map_err(|e| Error::Network(format!("Failed to connect UDP socket: {}", e)))?;

        self.connected = true;
        Ok(())
    }

    /// Send data to address
    pub fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        self.socket
            .send_to(buf, addr)
            .map_err(|e| Error::Network(format!("Failed to send UDP data: {}", e)))
    }

    /// Receive data from socket
    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        self.socket
            .recv_from(buf)
            .map_err(|e| Error::Network(format!("Failed to receive UDP data: {}", e)))
    }

    /// Send data (for connected sockets)
    pub fn send(&self, buf: &[u8]) -> Result<usize> {
        if !self.connected {
            return Err(Error::Network(
                "UDP socket is not connected".to_string(),
            ));
        }

        self.socket
            .send(buf)
            .map_err(|e| Error::Network(format!("Failed to send UDP data: {}", e)))
    }

    /// Receive data (for connected sockets)
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        if !self.connected {
            return Err(Error::Network(
                "UDP socket is not connected".to_string(),
            ));
        }

        self.socket
            .recv(buf)
            .map_err(|e| Error::Network(format!("Failed to receive UDP data: {}", e)))
    }

    /// Get local address
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|e| Error::Network(format!("Failed to get local address: {}", e)))
    }

    /// Set read timeout
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.socket
            .set_read_timeout(timeout)
            .map_err(|e| Error::Network(format!("Failed to set read timeout: {}", e)))
    }

    /// Set write timeout
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.socket
            .set_write_timeout(timeout)
            .map_err(|e| Error::Network(format!("Failed to set write timeout: {}", e)))
    }

    /// Set broadcast mode
    pub fn set_broadcast(&self, broadcast: bool) -> Result<()> {
        self.socket
            .set_broadcast(broadcast)
            .map_err(|e| Error::Network(format!("Failed to set broadcast mode: {}", e)))
    }
}

/// DNS resolution helper
/// Resolves hostname to SocketAddr
fn resolve_hostname(hostname: &str, port: u16) -> Result<SocketAddr> {
    // Try direct IP address first
    if let Ok(ip) = hostname.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    // DNS resolution
    let addr_str = format!("{}:{}", hostname, port);
    let mut addrs = addr_str
        .to_socket_addrs()
        .map_err(|e| Error::Network(format!("Failed to resolve hostname {}: {}", hostname, e)))?;

    addrs.next().ok_or_else(|| {
        Error::Network(format!("No addresses found for hostname: {}", hostname))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_tcp_listen_connect() {
        let port = 18888;

        // Start listener in background
        let handle = thread::spawn(move || {
            let listener = TcpSocketListener::listen(port).unwrap();
            let mut client = listener.accept().unwrap();

            let mut buf = [0u8; 5];
            let n = client.recv(&mut buf).unwrap();
            assert_eq!(n, 5);
            assert_eq!(&buf[..n], b"hello");

            client.send(b"world").unwrap();
        });

        // Give listener time to start
        thread::sleep(Duration::from_millis(100));

        // Connect and send data
        let mut sock = TcpSocket::connect("127.0.0.1", port).unwrap();
        assert!(sock.is_connected());
        assert!(!sock.is_server_mode());

        sock.send(b"hello").unwrap();

        let mut buf = [0u8; 5];
        let n = sock.recv(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"world");

        handle.join().unwrap();
    }

    #[test]
    fn test_tcp_timeout() {
        let sock = TcpSocket::connect_timeout("127.0.0.1", 19999, Duration::from_millis(100));
        assert!(sock.is_err()); // Should timeout (no server)
    }

    #[test]
    fn test_tcp_listener_local_only() {
        let listener = TcpSocketListener::listen_ex(18889, true).unwrap();
        let addr = listener.local_addr().unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn test_udp_send_recv() {
        let port1 = 18890;
        let port2 = 18891;

        let sock1 = UdpSocketWrapper::new(port1).unwrap();
        let sock2 = UdpSocketWrapper::new(port2).unwrap();

        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port2);
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port1);

        // Send from sock1 to sock2
        sock1.send_to(b"hello", addr2).unwrap();

        // Receive on sock2
        let mut buf = [0u8; 10];
        let (n, from_addr) = sock2.recv_from(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"hello");
        assert_eq!(from_addr.port(), port1);

        // Send reply
        sock2.send_to(b"world", addr1).unwrap();

        // Receive reply
        let (n, _) = sock1.recv_from(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..n], b"world");
    }

    #[test]
    fn test_udp_connected() {
        let port1 = 18892;
        let port2 = 18893;

        let mut sock1 = UdpSocketWrapper::new(port1).unwrap();
        let sock2 = UdpSocketWrapper::new(port2).unwrap();

        // Connect sock1 to sock2
        sock1.connect("127.0.0.1", port2).unwrap();

        // Send using connected API
        sock1.send(b"test").unwrap();

        // Receive on sock2
        let mut buf = [0u8; 10];
        let (n, _) = sock2.recv_from(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf[..n], b"test");
    }

    #[test]
    fn test_resolve_hostname() {
        let addr = resolve_hostname("127.0.0.1", 8080).unwrap();
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(addr.port(), 8080);
    }

    #[test]
    fn test_resolve_localhost() {
        let addr = resolve_hostname("localhost", 8080).unwrap();
        assert_eq!(addr.port(), 8080);
        // localhost can resolve to either IPv4 or IPv6
        assert!(
            addr.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST)
                || addr.ip() == IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
    }

    #[test]
    fn test_tcp_addresses() {
        let listener = TcpSocketListener::listen(18894).unwrap();
        let local_addr = listener.local_addr().unwrap();
        assert_eq!(local_addr.port(), 18894);

        let handle = thread::spawn(move || {
            let sock = listener.accept().unwrap();
            let peer = sock.peer_addr().unwrap();
            assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        });

        thread::sleep(Duration::from_millis(100));

        let sock = TcpSocket::connect("127.0.0.1", 18894).unwrap();
        let peer = sock.peer_addr().unwrap();
        assert_eq!(peer.port(), 18894);

        handle.join().unwrap();
    }
}
