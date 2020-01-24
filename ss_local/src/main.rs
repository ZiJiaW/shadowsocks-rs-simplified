extern crate tokio;
//#[macro_use]
extern crate futures;

use futures::future::{select};

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use std::sync::{Arc, Mutex};
use ss_local::Encypter;

use crate::Socks5::{ATYP_V4, ATYP_DN};
use futures::FutureExt;
use std::net::SocketAddr;

const SS_SERVER_ADDR: &'static str = "127.0.0.1:9002";
const PACKAGE_SIZE: usize = 8192;

#[allow(non_snake_case)]
mod Socks5 {
    pub const VER: u8 = 0x05;// protocol version
    pub const AUTH: u8 = 0x00;// auth type: no auth
    pub const CMD_TCP: u8 = 0x01;// tcp connection proxy
    //pub const CMD_UDP: u8 = 0x03;// udp request hasn't been implemented
    pub const ATYP_V4: u8 = 0x01;// ipv4 address type
    pub const ATYP_DN: u8 = 0x03;// domain name address type
    pub const REP_OK: u8 = 0x00;
}

enum RqAddr {
    IPV4(Vec<u8>),
    NAME(Vec<u8>),
}

async fn run(mut client: TcpStream, encrypter: Arc<Mutex<Encypter>>) -> io::Result<()>
{
    // socks5 handshake
    let mut buf = vec![0u8; 2];
    client.read_exact(&mut buf).await?;
    let mut len = 0;
    if buf[0] != Socks5::VER {
        println!("addr {:?} socks version is {}!", client.peer_addr().unwrap(), buf[0]);
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Wrong version!"));
    } else {
        //println!("version ok!");
        len = buf[1] as usize;
    }
    buf.resize(len, 0u8);
    client.read_exact(&mut buf).await?;
    if buf.iter().find(|&&x| x == Socks5::AUTH).is_none() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Wrong auth type!"));
    }
    client.write_all(&vec![Socks5::VER, Socks5::AUTH]).await?;

    // configure connection
    buf.resize(3, 0u8);
    client.read_exact(&mut buf).await?;
    if buf[0] != Socks5::VER {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Wrong version!"));
    } else if buf[1] != Socks5::CMD_TCP {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "No UDP support!"));
    }

    // get remote address
    buf.resize(1, 0u8);
    client.read_exact(&mut buf).await?;
    let addr = if buf[0] == ATYP_V4 {
        buf.resize(6, 0u8);
        client.read_exact(&mut buf).await?;
        Ok(RqAddr::IPV4(Vec::from(buf.clone())))
    } else if buf[0] == ATYP_DN {
        buf.resize(1, 0u8);
        client.read_exact(&mut buf).await?;
        let len = buf[0] as usize;
        buf.resize(len + 2, 0u8);
        client.read_exact(&mut buf).await?;
        //println!("address of domain name: {}", String::from_utf8(buf.clone()).unwrap());
        Ok(RqAddr::NAME(Vec::from(buf.clone())))
    } else {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "No UDP support!"))
    }?;

    // write response to client
    client.write_all(&vec![
        Socks5::VER, Socks5::REP_OK, 0x0, Socks5::ATYP_V4,
        0x0, 0x0, 0x0, 0x0, 0x10, 0x10
    ]).await?;

    // connect and push target address to remote server
    let header = match addr {
        RqAddr::IPV4(mut addr) => {// length = 7
            addr.insert(0, 0x1);// 0x1 127 0 0 1 0x0 0x50
            addr// indicate ipv4 addr (e.g. 127.0.0.1:80)
        },
        RqAddr::NAME(mut addr) => {// length = header[0]+3  (u8)
            assert!(addr.len() - 2 <= 255);
            addr.insert(0, (addr.len() - 2) as u8);// len(u8) www.google.com 0x0 0x50
            println!("New URI query: {}", String::from_utf8_lossy(&addr[1..addr.len()-2]));
            addr// indicate addr length
        }
    };

    let remote_addr: SocketAddr = SS_SERVER_ADDR.parse().unwrap();
    let mut remote = TcpStream::connect(&remote_addr).await?;

    remote.write_all(&header).await?;

    // forward data
    let (mut client_reader, mut client_writer) = client.split();

    let inner1 = Arc::clone(&encrypter);
    let inner2 = Arc::clone(&encrypter);

    let (mut remote_reader, mut remote_writer) = remote.split();

    let client_to_remote = async move {
        loop {
            let mut buf = vec![0u8; PACKAGE_SIZE];
            match client_reader.read(&mut buf).await {
                Ok(len) => {
                    if len == 0 {
                        break;
                    }
                    // encapsulate data
                    // structure: [0x34 0x12] [encryted data]
                    let mut data: Vec<u8> = inner1.lock().unwrap().encode(&buf[0..len]);
                    let len = data.len().to_le_bytes();
                    data.insert(0, len[1]);
                    data.insert(0, len[0]);

                    // write to remote server
                    if remote_writer.write_all(&data).await.is_err() {
                        break;
                    }
                },
                Err(_) => {
                    break;
                }
            }
        }
    };

    let remote_to_client = async move {
        loop {
            let mut buf = vec![0u8; 2];
            if remote_reader.read_exact(&mut buf).await.is_err() {
                break;
            }
            let len: usize = ((buf[1] as usize) << 8) | (buf[0] as usize);
            buf.resize(len, 0u8);
            if remote_reader.read_exact(&mut buf).await.is_err() {
                break;
            }
            let data = inner2.lock().unwrap().decode(&buf[0..len]);
            if client_writer.write_all(&data).await.is_err() {
                break;
            }
        }
    };

    // wait either one to close
    select(client_to_remote.boxed(), remote_to_client.boxed()).await;

    println!("connection close!");
    Ok(())
}

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:7962";
    let mut listener = TcpListener::bind(addr).await.unwrap();
    let encrypter = Arc::new(Mutex::new(Encypter::new()));

    let server = async move {
        loop {
            match listener.accept().await {
                Ok((socket, _)) => {
                    tokio::spawn(
                        run(socket, encrypter.clone())
                    );
                },
                Err(e) => println!("Error happened when accepting: {:?}", e),
            }
        }
    };

    println!("Local server listening on {}", addr);
    server.await;
}