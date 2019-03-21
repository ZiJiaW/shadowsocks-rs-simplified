extern crate tokio;
#[macro_use]
extern crate futures;
extern crate trust_dns_resolver;

use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;

use bytes::BufMut;
use bytes::BytesMut;

use std::net::*;
use tokio::runtime::current_thread::Runtime;
use trust_dns_resolver::ResolverFuture;
use trust_dns_resolver::config::*;

struct ReadAll {
    socket: TcpStream,
    rd: BytesMut,
}

impl ReadAll {
    fn new(socket: TcpStream) -> ReadAll {
        ReadAll{socket: socket, rd: BytesMut::new()}
    }

    fn fill_read_buf(&mut self) -> Poll<(), io::Error>
    {
        loop {
            self.rd.reserve(1024);
            let n = try_ready!(self.socket.read_buf(&mut self.rd));
            if n == 0 {
                return Ok(Async::Ready(()));
            }
        }
    }
}

impl Future for ReadAll {
    type Item = ();
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        //let t = self.fill_read_buf()?.is_ready();
        self.rd.reserve(1024);
        let n = try_ready!(self.socket.read_buf(&mut self.rd));
        println!("{}",self.rd.len());
        println!("{}", self.rd.capacity());
        println!("data: {}", String::from_utf8_lossy(&self.rd[..]));
        Ok(Async::Ready(()))
    }
}

fn main() {
    let addr = "127.0.0.1:9000".parse().unwrap();
    let listener = TcpListener::bind(&addr).unwrap();

    let remote_server = 
    listener.incoming().for_each(move |socket| {
        println!("new client {:?}!", socket.peer_addr().unwrap());
        let pro = 
        io::read(socket, vec![0; 200]).and_then(|(socket, data, len)| {
            println!("{}", len);
            println!("data: {:?}", String::from_utf8(data).unwrap());
            
            let resolver = ResolverFuture::new(
                ResolverConfig::default(),
                ResolverOpts::default()
            );
            resolver.and_then(|resolver| {
                resolver.lookup_ip("www.baidu.com")
            })
            .and_then(|ips| {
                let ip = ips.iter().next().unwrap();
                println!("ip: {:?}", ip);
                Ok(())
            })
            .map_err(|_| {io::Error::from(io::ErrorKind::InvalidData)})
        })
        .map_err(|e| { println!("Error happened in serving: {:?}", e); });


        tokio::spawn(pro);



        //tokio::spawn(ReadAll::new(socket).map_err(|e|{println!("error happened!");}));
        Ok(())
    })
    .map_err(|e| { println!("Error happened in serving: {:?}", e); });
    println!("Server listening on {:?}", addr);
    tokio::run(remote_server);
}
