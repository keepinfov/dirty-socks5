use tokio::io::copy_bidirectional;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, lookup_host};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
const AUTH_ENABLED: bool = true;
const UNAME: &str = "user";
const PASSWD: &str = "password";

const RFC1928_VER: u8 = 0x05;
const RFC1929_VER: u8 = 0x01;

#[repr(u8)]
enum AuthMethods {
    NoAuthRequired = 0x00,
    UsernamePassword = 0x02,
    NoAcceptableMethod = 0xff
}

#[repr(u8)]
enum Cmd {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

impl TryFrom<u8> for Cmd {
    type Error = u8;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Cmd::Connect),
            0x03 => Ok(Cmd::Bind),
            0x04 => Ok(Cmd::UdpAssociate),
            other => Err(other),
        }
    }
}

#[repr(u8)]
enum AddrType {
    IPv4 = 0x01,
    Domain = 0x03,
    IPv6 = 0x04,
}

impl TryFrom<u8> for AddrType {
    type Error = u8;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(AddrType::IPv4),
            0x03 => Ok(AddrType::Domain),
            0x04 => Ok(AddrType::IPv6),
            other => Err(other),
        }
    }
}

#[repr(u8)]
enum Reply {
    Succeeded = 0x00,
    GeneralServerFailure = 0x01,
    ConnectionNotALlowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TTLExpired = 0x06,
    CommandNotSupported = 0x07,
    AddrTypeNotSupported = 0x08
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();

    let listener = TcpListener::bind("0.0.0.0:1080").await?;
    log::info!("TCP Server listening on: {}", listener.local_addr()?);

    let active = Arc::new(AtomicUsize::new(0));

    loop {
        let (mut stream, addr) = listener.accept().await?;
        log::info!("Connected: {}", addr);

        let count = Arc::clone(&active);

        tokio::spawn(async move {
            count.fetch_add(1, Ordering::Relaxed);

            if stream.read_u8().await? != RFC1928_VER {
                return Ok(());
            }

            let nmethods = stream.read_u8().await? as usize;

            let mut methods = vec![0u8; nmethods];
            stream.read_exact(&mut methods).await?;

            match (
                AUTH_ENABLED,
                methods.contains(&(AuthMethods::NoAuthRequired as u8)),
                methods.contains(&(AuthMethods::UsernamePassword as u8)),
            ) {
                (true, _, true) => {
                    stream.write(&[RFC1928_VER, AuthMethods::UsernamePassword as u8]).await?;
                    auth_handle(&mut stream).await?;
                }
                (false, true, _) => {
                    stream.write(&[RFC1928_VER, AuthMethods::NoAuthRequired as u8]).await?;
                    request_handle(&mut stream).await?;
                }
                _ => {
                    stream.write(&[RFC1928_VER, AuthMethods::NoAcceptableMethod as u8]).await?;
                    return Ok(());
                }
            }

            let remaining = count.fetch_sub(1, Ordering::Relaxed) - 1;
            log::info!("{} disconnected (active {})", addr, remaining);

            Ok::<(), anyhow::Error>(())
        });
    }
}

// RFC-1929 Implementation
async fn auth_handle(stream: &mut TcpStream) -> anyhow::Result<()> {
    if stream.read_u8().await? != RFC1929_VER {
        return Ok(());
    }

    let ulen = stream.read_u8().await? as usize;

    let mut uname = vec![0u8; ulen];
    stream.read_exact(&mut uname).await?;

    let plen = stream.read_u8().await? as usize;

    let mut passwd = vec![0u8; plen];
    stream.read_exact(&mut passwd).await?;

    if uname == UNAME.as_bytes() && passwd == PASSWD.as_bytes() {
        log::info!("{} successfully authentificated!", stream.peer_addr()?.ip());
        stream.write(&[RFC1929_VER, 0x00]).await?;
        request_handle(stream).await
    } else {
        stream.write(&[RFC1929_VER, 0x67]).await?;
        stream.shutdown().await?;
        return Ok(());
    }
}

async fn request_handle(stream: &mut TcpStream) -> anyhow::Result<()> {
    if stream.read_u8().await? != RFC1928_VER {
        return Ok(());
    }

    let cmd = stream.read_u8().await?;
    match Cmd::try_from(cmd) {
        Ok(Cmd::Connect) => {
            let _rsv = stream.read_u8().await?;
            let atyp = stream.read_u8().await?;

            let address_ip = match AddrType::try_from(atyp) {
                Ok(AddrType::IPv4) => {
                    let mut ipv4_buf = [0u8; 4];
                    stream.read_exact(&mut ipv4_buf).await?;
                    IpAddr::V4(Ipv4Addr::from_octets(ipv4_buf))
                }
                Ok(AddrType::Domain) => {
                    let dlen = stream.read_u8().await? as usize;

                    let mut domain_buf = vec![0u8; dlen];
                    stream.read_exact(&mut domain_buf).await?;
                    let domain = String::from_utf8(domain_buf)?;

                    lookup_host((domain, 0)).await?.next().unwrap().ip()
                }
                Ok(AddrType::IPv4) => {
                    let mut ipv6_buf = [0u8; 16];
                    stream.read_exact(&mut ipv6_buf).await?;
                    IpAddr::V6(Ipv6Addr::from_octets(ipv6_buf))
                }
                Err(_) => {
                    stream
                        .write(&[RFC1928_VER, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                        .await?;
                    stream.shutdown().await?;
                    return Ok(());
                }
            };

            let mut address_port = [0u8; 2];
            stream.read_exact(&mut address_port).await?;
            let address_port = u16::from_be_bytes(address_port);

            let address = SocketAddr::new(address_ip, address_port);
            let mut out_stream = TcpStream::connect(address).await?;

            let mut response = Vec::new();
            response.extend_from_slice(&[RFC1928_VER, Reply::Succeeded as u8, 0x00]);

            let local_addr = out_stream.local_addr()?;
            let ip = local_addr.ip();
            let port = local_addr.port();

            match ip {
                IpAddr::V4(ipv4) => {
                    response.push(AddrType::IPv4 as u8);
                    response.extend_from_slice(&ipv4.octets());
                }
                IpAddr::V6(ipv6) => {
                    response.push(AddrType::IPv6 as u8);
                    response.extend_from_slice(&ipv6.octets());
                }
            }
            response.extend_from_slice(&port.to_be_bytes());

            stream.write_all(&response).await?;
            stream.flush().await?;

            copy_bidirectional(stream, &mut out_stream).await?;

            Ok(())
        }
        Ok(Cmd::Bind) => todo!("CMD BIND request handle"),
        Ok(Cmd::UdpAssociate) => todo!("CMD UDP ASSOCIATE request handle"),
        _ => {
            stream
                .write(&[RFC1928_VER, Reply::CommandNotSupported as u8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .await?;
            stream.shutdown().await?;
            return Ok(());
        }
    }
}
