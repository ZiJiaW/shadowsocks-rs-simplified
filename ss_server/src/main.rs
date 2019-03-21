extern crate tokio;
extern crate futures;
extern crate trust_dns_resolver;

use ss_local::Encypter;

use futures::future::{Either};

use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;

use std::sync::{Arc, Mutex};
use std::net::{Ipv4Addr, IpAddr, SocketAddr};

use trust_dns_resolver::ResolverFuture;
use trust_dns_resolver::config::*;

fn query_addr(addr: String, port: u16) -> impl Future<Item = SocketAddr, Error = io::Error>
{
    let resolver_future = ResolverFuture::new(
        ResolverConfig::default(),
        ResolverOpts::default()
    );
    resolver_future.and_then(move |resolver| {
        resolver.lookup_ip(&addr[..])
    })
    .and_then(move |ips| {
        let ip = ips.iter().next().unwrap();
        Ok(SocketAddr::new(ip, port))
    })
    .map_err(|e| {
        println!("dns error: {:?}",e);
        io::Error::new(io::ErrorKind::InvalidData, "Query DNS Error!")
    })
}

fn process(socket: TcpStream, encrypter: Arc<Mutex<Encypter>>)
{
    let process = io::read(socket, vec![0; 2048])
    .and_then(move |(socket, data, len)| {
        println!("get encrypted data len: {}", len);
        let mut data = encrypter.lock().unwrap().decode(&data[0..len]);
        //println!("get data len: {}", len);

        let (addr_future, request_data) = match data[0] {
            0x1 => {
                let addr = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
                let port = ((data[5] as u16) << 8) | (data[6] as u16);
                let data = data.split_off(7);
                (Either::A(future::ok::<SocketAddr, io::Error>(SocketAddr::new(IpAddr::V4(addr), port))), data)
            },
            length => {
                let length = length as usize;
                let port = ((data[length + 1] as u16) << 8) | (data[length + 2] as u16);
                let addr = String::from_utf8_lossy(&data[1..(length+1)]).to_string();
                println!("query address: {}", addr);
                let data = data.split_off(length + 3);
                (Either::B(query_addr(addr, port)), data)
            }
        };
        
        addr_future.and_then(|dst_addr| {
            TcpStream::connect(&dst_addr).and_then(move |dst_stream| {
                io::write_all(dst_stream, request_data)
                .and_then(|(dst_stream, _)| {
                    io::read(dst_stream, vec![0; 2048])
                    .and_then(|(_, buf, len)| {
                        println!("rcv len {}", len);
                        Ok(buf)
                    })
                })
            })
            .and_then(move |buf| {
                Ok((socket, buf, encrypter))
            })
        })
    })
    .and_then(|(socket, buf, encrypter)| {
        let response = encrypter.lock().unwrap().encode(&buf);
        io::write_all(socket, response)
        .and_then(|_|{
            println!("response sent!");
            Ok(())
        })
    })
    .map_err(|e| {
        println!("Error happened when fetching data: {:?}", e);
    });
    tokio::spawn(process);
}

fn main() {
    let encrypter = Arc::new(Mutex::new(Encypter::new()));
    let addr = "127.0.0.1:9002".parse().unwrap();
    let listener = TcpListener::bind(&addr).unwrap();

    let remote_server = 
    listener.incoming().for_each(move |socket| {
        println!("new client {:?}!", socket.peer_addr().unwrap());
        process(socket, Arc::clone(&encrypter));
        Ok(())
    })
    .map_err(|e| {
        println!("Error happened in serving: {:?}", e);
    });
    println!("Server listening on {:?}", addr);
    tokio::run(remote_server);
}
