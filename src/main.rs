use tokio::io::copy_bidirectional;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, lookup_host};

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
            let mut buf = [0u8; 256 + 2];

            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return Ok(()),
                Ok(_n) => {
                    if buf[0] != 0x05 {
                        return Ok(());
                    }

                    let nmethods = buf[1];
                    let methods = &buf[2..(nmethods + 2) as usize];
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
    let mut buf = [0u8; 515];
    match stream.read(&mut buf).await {
        Ok(0) | Err(_) => return Ok(()),
        Ok(_n) => {
            if buf[0] != 0x01 {
                return Ok(());
            }
            let ulen = buf[1] as usize;
            let uname: &str = &(String::from_utf8(buf[2..ulen + 2].to_vec())?);
            let plen = buf[2 + ulen] as usize;
            let passwd: &str =
                &(String::from_utf8(buf[2 + ulen + 1..2 + ulen + 1 + plen].to_vec())?);

            if uname == UNAME && passwd == PASSWD {
                log::info!("{} successfully authentificated!", stream.peer_addr()?.ip());
                stream.write(&[0x01, 0x00]).await?;
                request_handle(stream).await
            } else {
                stream.write(&[0x01, 0x67]).await?;
                stream.shutdown().await?;
                return Ok(());
            }
        }
    }
}

async fn request_handle(stream: &mut TcpStream) -> anyhow::Result<()> {
    let mut buf = [0u8; 263];
    match stream.read(&mut buf).await {
        Ok(0) | Err(_) => return Ok(()),
        Ok(_n) => {
            if buf[0] != 0x05 {
                return Ok(());
            }
            let cmd = buf[1];
            match cmd {
                0x01 => {
                    let atyp = buf[3];
                    match atyp {
                        0x01 => {
                            let address = format!(
                                "{}.{}.{}.{}:{}",
                                buf[4],
                                buf[5],
                                buf[6],
                                buf[7],
                                u16::from_be_bytes([buf[8], buf[9]])
                            );
                            let mut out_stream = TcpStream::connect(address).await?;
                            let mut response = Vec::new();
                            response.push(0x05);
                            response.push(0x00);
                            response.push(0x00);

                            let local_addr = out_stream.local_addr()?;
                            let ip = local_addr.ip();
                            let port = local_addr.port();

                            match ip {
                                std::net::IpAddr::V4(ipv4) => {
                                    response.push(0x01);
                                    response.extend_from_slice(&ipv4.octets());
                                }
                                std::net::IpAddr::V6(ipv6) => {
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
                        0x03 => {
                            let dlen = buf[4] as usize;
                            let domain = String::from_utf8(buf[5..5 + dlen].to_vec())?;
                            let port = u16::from_be_bytes([buf[5 + dlen], buf[5 + dlen + 1]]);

                            let address = lookup_host(format!("{}:{}", domain, port))
                                .await?
                                .next()
                                .unwrap();
                            let mut out_stream = TcpStream::connect(address).await?;
                            let mut response = Vec::new();
                            response.push(0x05);
                            response.push(0x00);
                            response.push(0x00);

                            let local_addr = out_stream.local_addr()?;
                            let ip = local_addr.ip();
                            let port = local_addr.port();

                            match ip {
                                std::net::IpAddr::V4(ipv4) => {
                                    response.push(0x01);
                                    response.extend_from_slice(&ipv4.octets());
                                }
                                std::net::IpAddr::V6(ipv6) => {
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
                        0x04 => {
                            let address = std::net::SocketAddrV6::new(
                                std::net::Ipv6Addr::from_octets(buf[4..20].try_into().unwrap()),
                                u16::from_be_bytes(buf[20..22].try_into().unwrap()),
                                0,
                                0,
                            );

                            let mut out_stream = TcpStream::connect(address).await?;
                            let mut response = Vec::new();
                            response.push(0x05);
                            response.push(0x00);
                            response.push(0x00);

                            let local_addr = out_stream.local_addr()?;
                            let ip = local_addr.ip();
                            let port = local_addr.port();

                            match ip {
                                std::net::IpAddr::V4(ipv4) => {
                                    response.push(0x01);
                                    response.extend_from_slice(&ipv4.octets());
                                }
                                std::net::IpAddr::V6(ipv6) => {
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
                        _ => {
                            stream
                                .write(&[
                                    0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                ])
                                .await?;
                            stream.shutdown().await?;
                            return Ok(());
                        }
                    }
                }
                0x02 => todo!("CMD BIND"),
                0x03 => todo!("CMD UDP ASSOCIATE"),
                _ => {
                    stream
                        .write(&[0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                        .await?;
                    stream.shutdown().await?;
                    return Ok(());
                }
            }
        }
    }
}
