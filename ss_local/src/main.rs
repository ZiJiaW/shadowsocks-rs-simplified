extern crate tokio;
//#[macro_use]
extern crate futures;
extern crate bytes;

use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use futures::future::{Either};

use std::sync::{Arc, Mutex};
use ss_local::Encypter;
//use bytes::{BytesMut, BufMut};

use std::iter;

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

// hand shake part of socks5 protocol
fn hand_shake(socket: TcpStream) -> impl Future<Item = TcpStream, Error = io::Error>
{
    io::read_exact(socket, vec![0u8; 2])
    .and_then(|(socket, buf)| {
        if buf[0] != Socks5::VER {
            println!("addr {:?} socks version is {}!", socket.peer_addr().unwrap(), buf[0]);
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Wrong version!"));
        } else {
            //println!("version ok!");
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
    //println!("handle connection now!");
    let check = io::read_exact(socket, vec![0u8; 3])
    .and_then(|(socket, buf)| {
        //println!("connect message: {:?}", buf);
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
            //println!("addr type: {:?}", buf);
            if buf[0] == Socks5::ATYP_V4 {
                Either::A(io::read_exact(socket, vec![0u8; 6])
                .and_then(|(socket, buf)| {
                    println!("addr of ip: {:?}", buf);
                    let addr = RqAddr::IPV4(Vec::from(buf));
                    Ok((socket, addr))
                }))
            } else if buf[0] == Socks5::ATYP_DN {
                Either::B(Either::A(io::read_exact(socket, vec![0u8])
                .and_then(|(socket, buf)| {
                    let len = buf[0];
                    io::read_exact(socket, vec![0u8; len as usize + 2])
                    .and_then(|(socket, buf)| {
                        let mut pr: Vec<u8> = buf.clone();
                        let addr = RqAddr::NAME(Vec::from(buf));
                        pr.split_off(pr.len() - 2);
                        println!("addr of domain name: {}", String::from_utf8(pr).unwrap());
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

// connect and transfer target address to remote
fn handle_address(client: TcpStream, addr: RqAddr)
    -> impl Future<Item = (TcpStream, TcpStream), Error = io::Error>
{
    println!("push address to remote server!");
    let header = match addr {
        RqAddr::IPV4(mut addr) => {// length = 7
            addr.insert(0, 0x1);// 0x1 127 0 0 1 0x0 0x50
            addr// indicate ipv4 addr (e.g. 127.0.0.1:80)
        },
        RqAddr::NAME(mut addr) => {// length = header[0]+3  (u8)
            assert!(addr.len() - 2 <= 255);
            addr.insert(0, (addr.len() - 2) as u8);// len(u8) www.google.com 0x0 0x50
            addr// indicate addr length
        }
    };
    let remote_addr = SS_SERVER_ADDR.parse().unwrap();

    TcpStream::connect(&remote_addr).and_then(move |remote| {
        io::write_all(remote, header)
        .and_then(move |(remote, _)| {
            Ok((client, remote))
        })
    })
}

// data proxy part
fn handle_proxy(client: TcpStream, remote: TcpStream, encrypter: Arc<Mutex<Encypter>>)
    -> impl Future<Item = (), Error = io::Error>
{
    //println!("handle proxy now!");

    let (client_reader, client_writer) = client.split();

    let encrypter_inner1 = Arc::clone(&encrypter);
    let encrypter_inner2 = Arc::clone(&encrypter);

    let (remote_reader, remote_writer) = remote.split();

    let iter = stream::iter_ok::<_, io::Error>(iter::repeat(()));

    let client_to_remote = iter.fold((client_reader, remote_writer), move |(reader, writer), _| {
        let encrypter = Arc::clone(&encrypter_inner1);
        io::read(reader, vec![0; PACKAGE_SIZE]).and_then(move |(reader, buf, len)| {
            //println!("read {} bytes from client;", len);
            // closed
            if len == 0 {
                Either::A(future::err(io::Error::new(io::ErrorKind::BrokenPipe, "client connection closed!")))
            } else {
                // encapsulate data
                // structure: [0x34 0x12] [encryted data]
                let mut data: Vec<u8> = encrypter.lock().unwrap().encode(&buf[0..len]);
                let len = data.len().to_le_bytes();
                data.insert(0, len[1]);
                data.insert(0, len[0]);
                
                // write to remote server
                Either::B(io::write_all(writer, data).and_then(move |(writer, _)| {
                    //println!("data sent to remote;");
                    Ok((reader, writer))
                }))
            }
        })
    })
    .map(|_|()).map_err(|_|{
        println!("browser client connection closed!");
    });

    let iter = stream::iter_ok::<_, io::Error>(iter::repeat(()));

    let remote_to_client = iter.fold((client_writer, remote_reader),
    move |(writer, reader), _| {
        let encrypter = Arc::clone(&encrypter_inner2);
        // first read 2 bytes of length
        io::read_exact(reader, vec![0u8; 2])
        .and_then(move |(reader, buf)| {
            let len: usize = ((buf[1] as usize) << 8) | (buf[0] as usize);
            io::read_exact(reader, vec![0; len])
            .and_then(move |(reader, buf)| {
                let data = encrypter.lock().unwrap().decode(&buf[0..len]);
                io::write_all(writer, data)
                .and_then(move |(writer, _)| {
                    Ok((writer, reader))
                })
            })
        })
    })
    .map(|_|()).map_err(|_|{
        println!("remote connection closed!");
    });

    let proxy = client_to_remote.select(remote_to_client);
    proxy.then(|_| {
        println!("proxy end!");
        Ok(())
    })
}

// Main processing logic
fn process(client: TcpStream, encrypter: Arc<Mutex<Encypter>>)
{
    let handler = hand_shake(client)
    .and_then(|client| {
        handle_connect(client)
    })
    .and_then(|(client, addr)| {
        handle_address(client, addr)
    })
    .and_then(move |(client, remote)| {
        handle_proxy(client, remote, encrypter)
    })
    .map_err(|e|{
        println!("Error happened in processing: {:?}", e);
    });
    tokio::spawn(handler);
}


fn main()
{
    let addr = "127.0.0.1:7962".parse().unwrap();
    let listener = TcpListener::bind(&addr).unwrap();

    let encrypter = Arc::new(Mutex::new(Encypter::new()));

    let local_server =
    listener.incoming().for_each(move |client| {
        println!("New connection from: {:?}", client.peer_addr().unwrap());
        process(client, Arc::clone(&encrypter));
        Ok(())
    })
    .map_err(|e| {
        println!("Error happened in serving: {:?}", e);
    });
    
    println!("Server listening on {:?}", addr);
    tokio::run(local_server);
}