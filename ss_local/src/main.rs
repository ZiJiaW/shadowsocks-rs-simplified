#[warn(non_snake_case)]

extern crate tokio;
#[macro_use]
extern crate futures;
extern crate bytes;

use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use futures::sync::mpsc;
use futures::future::{self, Either};
use bytes::{BytesMut, Bytes, BufMut};

use std::collections::HashMap;
use std::net::{SocketAddr, Ipv4Addr, IpAddr};
use std::sync::{Arc, Mutex};

use openssl::symm::{encrypt, Cipher, decrypt};

const SS_SERVER_ADDR: &'static str = "127.0.0.1:9002";

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
    IPV4(SocketAddr),
    NAME((String, u16)),
}

// simple AES encryption
struct Encypter {
    cipher: Cipher,
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl Encypter {
    fn new() -> Encypter
    {
        let cipher = Cipher::aes_128_cbc();
        let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F".to_vec();
        let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07".to_vec();
        Encypter {cipher, key, iv}
    }

    fn encode(&mut self, text: &[u8]) -> Vec<u8>
    {
        encrypt(self.cipher, &self.key, Some(&self.iv), text).unwrap()
    }

    fn decode(&mut self, text: &[u8]) -> Vec<u8>
    {
        decrypt(self.cipher, &self.key, Some(&self.iv), text).unwrap()
    }
}

// hand shake part of socks5 protocol
fn hand_shake(socket: TcpStream) -> impl Future<Item = TcpStream, Error = io::Error>
{
    io::read_exact(socket, vec![0u8; 2])
    .and_then(|(socket, buf)| {
        if buf[0] != Socks5::VER {
            println!("addr {:?} socks version is {}!", socket.peer_addr().unwrap(), buf[0]);
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Wrong version!"));
        } else {
            let len = buf[1];
            Ok((socket, len))
        }
    })
    .and_then(|(socket, len)| {
        io::read_exact(socket, vec![0u8; len as usize])
        .and_then(|(socket, buf)| {
            match buf.iter().find(|&&x| x == Socks5::AUTH) {
                Some(_) => Ok(socket),
                None => Err(io::Error::new(io::ErrorKind::PermissionDenied, "Wrong auth type!"))
            }
        })
    })
    .and_then(|socket| {
        io::write_all(socket, vec![Socks5::VER, Socks5::AUTH])
        .and_then(|(socket, _)| {
            Ok(socket)
        })
    })
}

// connection configure part
fn handle_connect(socket: TcpStream) -> impl Future<Item = (TcpStream, RqAddr), Error = io::Error>
{
    let check = io::read_exact(socket, vec![0u8; 3])
    .and_then(|(socket, buf)| {
        if buf[0] != Socks5::VER {
            Err(io::Error::new(io::ErrorKind::InvalidData, "Wrong version!"))
        } else if buf[1] != Socks5::CMD_TCP {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "No UDP support!"))
        } else {
            Ok(socket)
        }    
    });
    
    check.and_then(|socket| {
        io::read_exact(socket, vec![0u8]).and_then(|(socket, buf)| {
            if buf[3] == Socks5::ATYP_V4 {
                Either::A(io::read_exact(socket, vec![0u8; 6])
                .and_then(|(socket, buf)| {
                    let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                    let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
                    let addr = RqAddr::IPV4(SocketAddr::new(IpAddr::V4(addr), port));
                    Ok((socket, addr))
                }))
            } else if buf[3] == Socks5::ATYP_DN {
                Either::B(Either::A(io::read_exact(socket, vec![0u8])
                .and_then(|(socket, buf)| {
                    let len = buf[0];
                    io::read_exact(socket, vec![0u8; len as usize + 2])
                    .and_then(|(socket, buf)| {
                        let (name, port) = buf.split_at(buf.len() - 2);
                        let port = ((port[0] as u16) << 8) | (port[1] as u16);
                        let addr = RqAddr::NAME((String::from_utf8(name.to_vec()).unwrap(), port));
                        Ok((socket, addr))
                    })
                })))
            } else {
                Either::B(Either::B(
                    Err(io::Error::new(io::ErrorKind::PermissionDenied, "No UDP support!")).into_future()
                ))
            }
        })
    })
    .and_then(|(socket, addr)| {// write response to client
        let response: Vec<u8> = vec![
            Socks5::VER, Socks5::REP_OK, 0x0, Socks5::ATYP_V4,
            0x0, 0x0, 0x0, 0x0, 0x10, 0x10
        ];
        io::write_all(socket, response)
        .and_then(|(socket, _)| {
            Ok((socket, addr))
        })
    })
}

// Main processing logic
fn process(client: TcpStream, remote: Arc<Mutex<TcpStream>>, encrypter: Arc<Mutex<Encypter>>)
{
    let handler = hand_shake(client)
    .and_then(|client| {
        handle_connect(client)
    })
    // .and_then(|(client, addr)| {

    // })
    .map(|_|{})
    .map_err(|_|{});
    tokio::spawn(handler);
}


fn main()
{
    let addr = "127.0.0.1:7962".parse().unwrap();
    let listener = TcpListener::bind(&addr).unwrap();

    let encrypter = Arc::new(Mutex::new(Encypter::new()));
    let data = encrypter.clone().lock().unwrap().encode(&vec![1,2,3,4]);
    println!("encrypted data: {:?}", data);
    let data = encrypter.clone().lock().unwrap().decode(&data);
    println!("decrypted data: {:?}", data);

    let remote_addr = SS_SERVER_ADDR.parse().unwrap();

    let local_server = TcpStream::connect(&remote_addr)
    .and_then(move |remote| {
        println!("Successfully connect to remote server: {:?}", remote.peer_addr().unwrap());
        let shared_remote = Arc::new(Mutex::new(remote));
        listener.incoming().for_each(move |client| {
            process(client, Arc::clone(&shared_remote), Arc::clone(&encrypter));
            Ok(())
        })
    })
    .map_err(|e| {
        println!("Error happened: {:?}", e);
    });
    
    println!("Server listening on {:?}", addr);
    tokio::run(local_server);
}