extern crate tokio;
extern crate futures;
extern crate trust_dns_resolver;

use ss_local::Encypter;

use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use tokio::runtime::current_thread::Runtime;

use std::sync::{Arc, Mutex};
use std::net::{Ipv4Addr, IpAddr, SocketAddr};

use trust_dns_resolver::Resolver;
use trust_dns_resolver::ResolverFuture;
use trust_dns_resolver::config::*;

fn query_dns(name: &str) -> IpAddr
{
    let nameserver = NameServerConfigGroup::cloudflare();
    let config = ResolverConfig::from_parts(None, vec![], nameserver);
    let resolver = Resolver::new(config, ResolverOpts::default()).unwrap();
    let response = resolver.lookup_ip(name).unwrap();
    response.iter().next().unwrap()


// We need a Tokio reactor::Core to run the resolver
//  this is responsible for running all Future tasks and registering interest in IO channels
// let mut io_loop = Runtime::new().unwrap();
//     let resolver = ResolverFuture::new(ResolverConfig::default(), ResolverOpts::default());
// The resolver we just constructed is a Future wait for the actual Resolver
// let resolver = io_loop.block_on(resolver).unwrap();

// Lookup the IP addresses associated with a name.
// This returns a future that will lookup the IP addresses, it must be run in the Core to
//  to get the actual result.
// let lookup_future = resolver.lookup_ip("www.example.com.");

// Run the lookup until it resolves or errors
// let mut response = io_loop.block_on(lookup_future).unwrap();
}


fn process(socket: TcpStream, encrypter: Arc<Mutex<Encypter>>)
{
    let process = io::read(socket, vec![0; 2048])
    .and_then(move |(socket, data, len)| {
        println!("get encrypted data len: {}", len);
        let mut data = encrypter.lock().unwrap().decode(&data[0..len]);
        //println!("get data len: {}", len);

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
                let ip = query_dns(&String::from_utf8_lossy(addr));
                let data = data.split_off(length+3);
                (SocketAddr::new(ip, port), data)
            }
        };
        
        TcpStream::connect(&dst_addr).and_then(move |dst_stream| {
            io::write_all(dst_stream, data)
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
    .map_err(|e| {
        println!("Error happened in serving: {:?}", e);
    });
    println!("Server listening on {:?}", addr);
    tokio::run(remote_server);
}
