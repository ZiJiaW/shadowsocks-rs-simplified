extern crate tokio;
#[macro_use]
extern crate futures;
extern crate bytes;

use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use futures::future::{Either};

use std::sync::{Arc, Mutex};
use ss_local::Encypter;
use bytes::{BytesMut, BufMut};

const SS_SERVER_ADDR: &'static str = "127.0.0.1:9002";

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

// handle message transfer task
// receive from remote server and decrypt
struct RcvFromRemote {
    client: Arc<Mutex<TcpStream>>,
    remote: Arc<Mutex<TcpStream>>,
    rd: BytesMut,
    encrypter: Arc<Mutex<Encypter>>,
}

impl RcvFromRemote {
    fn new(
        client: Arc<Mutex<TcpStream>>,
        remote: Arc<Mutex<TcpStream>>,
        encrypter: Arc<Mutex<Encypter>>
    ) -> RcvFromRemote {
        RcvFromRemote{
            client, remote, rd: BytesMut::new(), encrypter,
        }
    }
}

impl Future for RcvFromRemote {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error>
    {

    }
}

// receivr from client(browser) and encode
struct RcvFromClient {
    client: Arc<Mutex<TcpStream>>,
    remote: Arc<Mutex<TcpStream>>,
    rd: BytesMut,
    encrypter: Arc<Mutex<Encypter>>,
    dst: BytesMut,
    read_done: bool,
    res_len: u32,
}

impl RcvFromClient {
    fn new(
        client: Arc<Mutex<TcpStream>>,
        remote: Arc<Mutex<TcpStream>>,
        encrypter: Arc<Mutex<Encypter>>,
        dst: BytesMut,
    ) -> RcvFromClient {
        RcvFromClient {
            client, remote, rd: BytesMut::new(), encrypter, dst, read_done: false, res_len: 0,
        }
    }
}

impl Future for RcvFromCleint {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error>
    {
        loop {
            if !self.read_done && res_len == 0 {
                self.rd.reserve(2048);
                let n = try_ready!(self.client.lock().unwrap().read_buf(&mut self.rd));
                if n == 0 {
                    self.read_done = true;
                } else {
                    res_len += n;
                }
            }

            while res_len != 0 {
                let mut wd = self.dst.clone();
                wd.reserve(self.rd.len());
                wd.put(&self.rd);
                let mut wd = BytesMut::from(self.encrypter.lock().unwrap().encode(&wd));
                let n = try_ready!(self.remote.lock().unwrap().poll_write(&wd));
                assert!(n > 0);
                
            }
            
        }
    }
}
//---------------------------------------------------//
struct Transfer {
    client: TcpStream,
    remote: TcpStream,
    rd: BytesMut,
    encrypter: Arc<Mutex<Encypter>>,
    dst: RqAddr,
    sent_done: bool,
}

impl Transfer {
    fn new(client: TcpStream, remote: TcpStream, encrypter: Arc<Mutex<Encypter>>, dst: RqAddr) -> Transfer
    {
        Transfer{
            client, remote, rd: BytesMut::new(), encrypter, dst, sent_done: false, 
        }
    }
}

impl Future for Transfer {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error>
    {
        // read message from client
        if !self.sent_done {
            self.rd.reserve(2048);
            let n = try_ready!(self.client.read_buf(&mut self.rd));
            if n == 0 {
                return Ok(Async::Ready(()));// closed
            }
            let mut dst = match &mut self.dst {
                RqAddr::IPV4(addr) => {
                    addr.insert(0, 0x1);// 0x1 127 0 0 1 0x0 0x50
                    BytesMut::from(addr.clone())// indicate ipv4 addr
                },
                RqAddr::NAME(addr) => {
                    //println!("addr is {:?}", addr);
                    assert!(addr.len() - 2 <= 255);
                    addr.insert(0, (addr.len() - 2) as u8);// len(u8) www.google.com 0x0 0x50
                    BytesMut::from(addr.clone())// indicate addr length
                }
            };
            println!("received data length: {}", self.rd.len());
            //println!("received data: {}", String::from_utf8_lossy(&self.rd));
            dst.reserve(self.rd.len());
            dst.put(&self.rd);
            let mut dst = BytesMut::from(self.encrypter.lock().unwrap().encode(&dst));
            println!("{} data to send!", dst.len());
            //println!("sent data {:?}", dst);
            while !dst.is_empty() {
                let n = try_ready!(self.remote.poll_write(&dst));
                assert!(n > 0);
                dst.split_to(n);// discard
            }
            println!("all data sent!");
            self.sent_done = true;
        }
        //--------------------read from romote now---------------------------
        self.rd.clear();
        self.rd.reserve(10240);
        let n = try_ready!(self.remote.read_buf(&mut self.rd));
        if n == 0 {
            return Ok(Async::Ready(()));
        }
        println!("remote message len is {}", n);
        let mut data = BytesMut::from(self.encrypter.lock().unwrap().decode(&self.rd[0..n]));
        while !data.is_empty() {
            let n = try_ready!(self.client.poll_write(&data));
            assert!(n > 0);
            data.split_to(n);
        }
        println!("response ok!");
        Ok(Async::Ready(()))
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

fn handle_proxy(client: TcpStream, encrypter: Arc<Mutex<Encypter>>, addr: RqAddr)
    -> impl Future<Item = (), Error = io::Error>
{
    println!("handle proxy now!");
    let remote_addr = SS_SERVER_ADDR.parse().unwrap();

    TcpStream::connect(&remote_addr).and_then(move |remote| {
        Transfer::new(client, remote, encrypter, addr)
    })
}

// Main processing logic
fn process(client: TcpStream, encrypter: Arc<Mutex<Encypter>>)
{
    let handler = hand_shake(client)
    .and_then(|client| {
        handle_connect(client)
    })
    .and_then(move |(client, addr)| {
        handle_proxy(client, encrypter, addr)
    })
    .map_err(|e|{ println!("Error happened in processing: {:?}", e); });
    tokio::spawn(handler);
}


fn main()
{
    let addr = "127.0.0.1:7962".parse().unwrap();
    let listener = TcpListener::bind(&addr).unwrap();

    let encrypter = Arc::new(Mutex::new(Encypter::new()));

    let mut newen = Encypter::new();

    let data = BytesMut::from(vec![1,2,3,4,5,6]);
    let enc = encrypter.lock().unwrap().encode(&data);
    println!("enc {:?}", enc);
    let dec = newen.decode(&enc);
    println!("{:?}", dec);

    let local_server = 
    listener.incoming().for_each(move |client| {
        println!("New connection from: {:?}", client.peer_addr().unwrap());
        process(client, Arc::clone(&encrypter));
        // let mut buf = BytesMut::new();
        // buf.reserve(1024);
        // buf.resize(1024, 0x1);
        // let a = io::read(client, buf).and_then(|(socket, buf, len)|{
        //     println!("get data {:?}, len ", buf);
        //     Ok(())
        // }).map(|_|{}).map_err(|_|{});
        // tokio::spawn(a);
        Ok(())
    })
    .map_err(|e| {
        println!("Error happened in serving: {:?}", e);
    });
    
    println!("Server listening on {:?}", addr);
    tokio::run(local_server);
}