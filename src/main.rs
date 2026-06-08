use tokio::io::copy_bidirectional;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, lookup_host};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
const AUTH_ENABLED: bool = true;
const UNAME: &str = "user";
const PASSWD: &str = "password";

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

            if stream.read_u8().await? != 0x05 {
                return Ok(());
            }

            let nmethods = stream.read_u8().await? as usize;

            let mut methods = vec![0u8; nmethods];
            stream.read_exact(&mut methods).await?;

            match (
                AUTH_ENABLED,
                methods.contains(&0x00),
                methods.contains(&0x02),
            ) {
                (true, _, true) => {
                    stream.write(&[0x05, 0x02]).await?;
                    auth_handle(&mut stream).await?;
                }
                (false, true, _) => {
                    stream.write(&[0x05, 0x00]).await?;
                    request_handle(&mut stream).await?;
                }
                _ => {
                    stream.write(&[0x05, 0xff]).await?;
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
    if stream.read_u8().await? != 0x01 {
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
        stream.write(&[0x01, 0x00]).await?;
        request_handle(stream).await
    } else {
        stream.write(&[0x01, 0x67]).await?;
        stream.shutdown().await?;
        return Ok(());
    }
}

async fn request_handle(stream: &mut TcpStream) -> anyhow::Result<()> {
    if stream.read_u8().await? != 0x05 {
        return Ok(());
    }

    let cmd = stream.read_u8().await?;
    match cmd {
        0x01 => {
            let _rsv = stream.read_u8().await?;
            let atyp = stream.read_u8().await?;

            let address_ip = match atyp {
                0x01 => {
                    let mut ipv4_buf = [0u8; 4];
                    stream.read_exact(&mut ipv4_buf).await?;
                    IpAddr::V4(Ipv4Addr::from_octets(ipv4_buf))
                }
                0x03 => {
                    let dlen = stream.read_u8().await? as usize;

                    let mut domain_buf = vec![0u8; dlen];
                    stream.read_exact(&mut domain_buf).await?;
                    let domain = String::from_utf8(domain_buf)?;

                    lookup_host((domain, 0)).await?.next().unwrap().ip()
                }
                0x04 => {
                    let mut ipv6_buf = [0u8; 16];
                    stream.read_exact(&mut ipv6_buf).await?;
                    IpAddr::V6(Ipv6Addr::from_octets(ipv6_buf))
                }
                _ => {
                    stream
                        .write(&[0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
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
            response.extend_from_slice(&[0x05, 0x00, 0x00]);

            let local_addr = out_stream.local_addr()?;
            let ip = local_addr.ip();
            let port = local_addr.port();

            match ip {
                IpAddr::V4(ipv4) => {
                    response.push(0x01);
                    response.extend_from_slice(&ipv4.octets());
                }
                IpAddr::V6(ipv6) => {
                    response.push(0x04);
                    response.extend_from_slice(&ipv6.octets());
                }
            }
            response.extend_from_slice(&port.to_be_bytes());

            stream.write_all(&response).await?;
            stream.flush().await?;

            copy_bidirectional(stream, &mut out_stream).await?;

            Ok(())
        }
        0x02 => todo!("CMD BIND request handle"),
        0x03 => todo!("CMD UDP ASSOCIATE request handle"),
        _ => {
            stream
                .write(&[0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .await?;
            stream.shutdown().await?;
            return Ok(());
        }
    }
}
