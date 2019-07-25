extern crate tokio;
#[macro_use]
extern crate futures;
extern crate trust_dns_resolver;
extern crate trust_dns;

use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;

use bytes::BufMut;
use bytes::BytesMut;

use std::net::*;
use tokio::runtime::current_thread::Runtime;
use trust_dns_resolver::ResolverFuture;
use trust_dns_resolver::config::*;

use trust_dns::client::{Client, ClientConnection, ClientStreamHandle, SyncClient, ClientFuture, ClientHandle};
use trust_dns::udp::UdpClientConnection;
use trust_dns::udp::UdpClientStream;

use std::net::Ipv4Addr;
use std::str::FromStr;
use trust_dns::op::DnsResponse;
use trust_dns::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns::rr::rdata::key::KEY;

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
            //let mut runtime = Runtime::new().unwrap();
        let stream = UdpClientStream::new(([114,114,114,114], 53).into());
        let (bg, mut client) = ClientFuture::connect(stream);
        tokio::spawn(bg);
        println!("bg spawned!");
        let query = client.query(Name::from_str("www.baidu.com.").unwrap(), DNSClass::IN, RecordType::A);

        println!("111");
        // let response = query.wait().unwrap();
        // println!("222");
        // if let &RData::A(addr) = response.answers()[1].rdata() {
        //     println!("{:?}", addr);
        //     //assert_eq!(addr, Ipv4Addr::new(93, 184, 216, 34));
        // }

        let pro = query.and_then(|response| {
            println!("ok");
            if let &RData::A(addr) = response.answers()[1].rdata() {
                println!("{:?}", addr);
                //assert_eq!(addr, Ipv4Addr::new(93, 184, 216, 34));
            }
            Ok(())
        }).map_err(|_|{});

        tokio::spawn(pro);
        Ok(())
    })
    .map_err(|e| { println!("Error happened in serving: {:?}", e); });
    println!("Server listening on {:?}", addr);
    tokio::run(remote_server);

    // sync use-------------------------------------------


    // let address = "114.114.114.114:53".parse().unwrap();
    // let conn = UdpClientConnection::new(address).unwrap();

    // let client = SyncClient::new(conn);

    // let name = Name::from_str("www.baidu.com.").unwrap();
    // let response = client.query(&name, DNSClass::IN, RecordType::A).unwrap();

    // let answers = response.answers();

    // let mut fip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    // for r in answers
    // {
    //     if r.rdata().to_record_type() == RecordType::A {
    //         if let Some(ip) = r.rdata().to_ip_addr() {
    //             fip = ip;
    //             break;
    //         }
    //     }
    // };

    // println!("final ip {:?}", fip);

    // async dns with tokio

}
