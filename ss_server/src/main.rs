extern crate tokio;
extern crate futures;
extern crate trust_dns_resolver;

use ss_local::Encypter;

use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;

use std::sync::{Arc, Mutex};
use std::net::{Ipv4Addr, IpAddr, SocketAddr};

use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::{ResolverConfig, NameServerConfigGroup, ResolverOpts};

fn query_dns(name: &str) -> IpAddr
{
    let nameserver = NameServerConfigGroup::cloudflare();
    let config = ResolverConfig::from_parts(None, vec![], nameserver);
    let resolver = Resolver::new(config, ResolverOpts::default()).unwrap();
    let response = resolver.lookup_ip(name).unwrap();
    response.iter().next().unwrap()
}


fn process(socket: TcpStream, encrypter: Arc<Mutex<Encypter>>)
{
    let process = io::read_to_end(socket, Vec::with_capacity(1024))
    .and_then(move |(socket, data)| {
        let mut data = encrypter.lock().unwrap().decode(&data);
        println!("get data: {:?}", data);
        let (dst_addr, data) = match data[0] {
            0x1 => {
                let addr = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
                let port = ((data[5] as u16) << 8) | (data[6] as u16);
                let data = data.split_off(7);
                (SocketAddr::new(IpAddr::V4(addr), port), data)
            },
            length => {
                let length = length as usize;
                let port = ((data[length + 1] as u16) << 8) | (data[length + 2] as u16);
                let addr = &data[1..length];
                println!("query address: {}", String::from_utf8(addr.to_vec()).unwrap());
                let ip = query_dns(& String::from_utf8_lossy(addr));
                let data = data.split_off(length+3);
                (SocketAddr::new(ip, port), data)
            }
        };
        
        TcpStream::connect(&dst_addr).and_then(move |dst_stream| {
            io::write_all(dst_stream, data)
            .and_then(|(dst_stream, _)| {
                io::read_to_end(dst_stream, Vec::with_capacity(1024))
                .and_then(|(_, buf)| {
                    Ok(buf)
                })
            })
        })
        .and_then(move |buf| {
            Ok((socket, buf, encrypter))
        })
    })
    .and_then(|(socket, buf, encrypter)| {
        let response = encrypter.lock().unwrap().encode(&buf);
        io::write_all(socket, response)
        .and_then(|_|{
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
    .map_err(|e| { println!("Error happened in serving: {:?}", e); });
    println!("Server listening on {:?}", addr);
    tokio::run(remote_server);
}
