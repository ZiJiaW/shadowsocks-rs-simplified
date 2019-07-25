extern crate tokio;
extern crate futures;
extern crate trust_dns;

use ss_local::Encypter;

use futures::future::{Either};

use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;

use std::sync::{Arc, Mutex, RwLock};
use std::net::{Ipv4Addr, IpAddr, SocketAddr};
use std::collections::HashMap;

use trust_dns::client::{ClientFuture, ClientHandle};
use trust_dns::rr::{DNSClass, Name, RecordType};
use std::str::FromStr;
use trust_dns::udp::UdpClientStream;

use std::iter;

const PACKAGE_SIZE: usize = 8196;

//handle dns query
fn query_addr2(mut addr: String, port: u16) -> impl Future<Item = SocketAddr, Error = io::Error>
{
    // initialize client
    let stream = UdpClientStream::new(([114,114,114,114], 53).into());
    let (bg, mut client) = ClientFuture::connect(stream);
    tokio::spawn(bg);
    addr.push('.');
    // get response future
    let query = client.query(Name::from_str(&addr[..]).unwrap(), DNSClass::IN, RecordType::A);

    query.and_then(move |response| {
        let answers = response.answers();
        let ip = answers.iter().filter(|r| {
            r.rdata().to_record_type() == RecordType::A
        }).map(|r| {
            r.rdata().to_ip_addr().unwrap()
        }).next().unwrap();

        Ok(SocketAddr::new(ip, port))
    }).map_err(|_| {
        io::Error::new(io::ErrorKind::Other, "Query DNS Error!")
    })

}

// connect target address
fn handle_connect(local: TcpStream, dns_map: Arc<RwLock<HashMap<String, IpAddr>>>)
    -> impl Future<Item = (TcpStream, TcpStream), Error = io::Error>
{
    io::read_exact(local, vec![0u8; 1])
    .and_then(move |(local, buf)| {
        match buf[0] {
            0x1 => {
                Either::A(io::read_exact(local, vec![0u8; 6])
                .and_then(|(local, buf)| {
                    let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                    let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
                    let dst_addr = SocketAddr::new(IpAddr::V4(ip), port);
                    TcpStream::connect(&dst_addr).and_then(move |dst| {
                        Ok((local, dst))
                    })
                }))
            },
            length => {
                let length = length as usize;
                Either::B(io::read_exact(local, vec![0u8; length + 2])
                .and_then(move |(local, buf)| {
                    let port = ((buf[length] as u16) << 8) | (buf[length + 1] as u16);
                    let addr = String::from_utf8_lossy(&buf[0..length]).to_string();
                    println!("connecting: {}", addr);
                    let read_map = dns_map.read().unwrap();
                    if read_map.contains_key(&addr)
                    {
                        println!("addr {} has been found", addr);
                        let ip = read_map.get(&addr).unwrap();
                        let dst_addr = SocketAddr::new(ip.clone(), port);
                        Either::A(TcpStream::connect(&dst_addr).and_then(move |dst| {
                            Ok((local, dst))
                        }))
                    }
                    else
                    {
                        drop(read_map);
                        Either::B(query_addr2(addr.clone(), port).and_then(move |dst_addr| {
                            println!("saved addr {} is {:?}", addr,  dst_addr.ip());
                            dns_map.write().unwrap().insert(addr, dst_addr.ip());
                            TcpStream::connect(&dst_addr).and_then(move |dst| {
                                Ok((local, dst))
                            })
                        }))
                    } 
                }))
            }
        }
    })
}

// handle data transfer
fn handle_proxy(local: TcpStream, dst: TcpStream, encrypter: Arc<Mutex<Encypter>>)
    -> impl Future<Item = (), Error = io::Error>
{
    let (local_reader, local_writer) = local.split();
    let (dst_reader, dst_writer) = dst.split();
    let encrypter_inner1 = Arc::clone(&encrypter);
    let encrypter_inner2 = Arc::clone(&encrypter);

    let iter = stream::iter_ok::<_, io::Error>(iter::repeat(()));
    let local_to_dst = iter.fold((local_reader, dst_writer), move |(reader, writer), _| {
        let encrypter = Arc::clone(&encrypter_inner1);
        io::read_exact(reader, vec![0u8; 2])
        .and_then(move |(reader, buf)| {
            let len: usize = ((buf[1] as usize) << 8) | (buf[0] as usize);
            io::read_exact(reader, vec![0u8; len])
            .and_then(move |(reader, buf)| {
                let data = encrypter.lock().unwrap().decode(&buf[0..len]);
                io::write_all(writer, data).and_then(move|(writer, _)| {
                    Ok((reader, writer))
                })
            })
        })
    }).map(|_|()).map_err(|_|{
        println!("browser client connection closed!");
    });

    let iter = stream::iter_ok::<_, io::Error>(iter::repeat(()));
    let dst_to_local = iter.fold((dst_reader, local_writer), move |(reader, writer), _| {
        let encrypter = Arc::clone(&encrypter_inner2);
        io::read(reader, vec![0u8; PACKAGE_SIZE]).and_then(move |(reader, buf, len)| {
            //println!("read {} bytes from dst;", len);
            if len == 0 {
                Either::A(future::err(io::Error::new(io::ErrorKind::BrokenPipe, "dst connection closed!")))
            } else {
                let mut data: Vec<u8> = encrypter.lock().unwrap().encode(&buf[0..len]);
                let len = data.len().to_le_bytes();
                data.insert(0, len[1]);
                data.insert(0, len[0]);
                Either::B(io::write_all(writer, data).and_then(move |(writer, _)| {
                    Ok((reader, writer))
                }))
            }
        })
    }).map(|_|()).map_err(|_|{
        println!("browser client connection closed!");
    });

    let proxy = local_to_dst.select(dst_to_local);
    proxy.then(|_| {
        println!("proxy end!");
        Ok(())
    })
}


// main processing logic
fn process(socket: TcpStream, encrypter: Arc<Mutex<Encypter>>, dns_map: Arc<RwLock<HashMap<String, IpAddr>>>)
{
    let handler = handle_connect(socket, dns_map)
    .and_then(move |(local, dst)| {
        handle_proxy(local, dst, encrypter)
    })
    .map_err(|e| {
        println!("Error happened in processing: {:?}", e);
    });
    tokio::spawn(handler);
}

fn main() {
    let encrypter = Arc::new(Mutex::new(Encypter::new()));
    let addr = "127.0.0.1:9002".parse().unwrap();
    let listener = TcpListener::bind(&addr).unwrap();
    let dns_map = Arc::new(RwLock::new(HashMap::new()));

    let remote_server = 
    listener.incoming().for_each(move |socket| {
        println!("new client {:?}!", socket.peer_addr().unwrap());
        process(socket, Arc::clone(&encrypter), Arc::clone(&dns_map));
        Ok(())
    })
    .map_err(|e| {
        println!("Error happened in serving: {:?}", e);
    });
    println!("Server listening on {:?}", addr);
    tokio::run(remote_server);
}
