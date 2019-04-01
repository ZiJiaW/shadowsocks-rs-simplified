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

use std::iter;

fn query_addr(addr: String, port: u16) -> impl Future<Item = SocketAddr, Error = io::Error>
{
    let resolver_future = ResolverFuture::new(
        ResolverConfig::cloudflare(),
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
    let process = io::read(socket, vec![0; 102400])
    .and_then(move |(socket, data, len)| {
        println!("get encrypted data len: {}", len);
        if len == 0 {
            return Either::A(future::err(io::Error::from(io::ErrorKind::NotConnected)));
        }
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
        Either::B(
        addr_future.and_then(|dst_addr| {
            TcpStream::connect(&dst_addr).and_then(move |dst_stream| {
                io::write_all(dst_stream, request_data)
                .and_then(|(dst_stream, _)| {
                    io::read(dst_stream, vec![0; 102400])
                    .and_then(|(dst_stream, buf, len)| {
                        println!("rcv len is {}", len);
                        Ok((dst_stream, buf, len))
                    })
                })
            })
            .and_then(move |(dst_stream, buf, len)| {
                Ok((socket, dst_stream, buf, len, encrypter))
            })
        })
        )
    })
    .and_then(|(socket, dst_stream, buf, len, encrypter)| {
        let response = encrypter.lock().unwrap().encode(&buf[0..len]);
        io::write_all(socket, response)
        .and_then(move |(socket, _)|{
            //println!("response sent!");
            //Ok(())
            // forward data until connection closed
            let encrypter_inner1 = Arc::clone(&encrypter);
            let encrypter_inner2 = Arc::clone(&encrypter);

            let (local_reader, local_writer) = socket.split();
            let (dst_reader, dst_writer) = dst_stream.split();

            let iter = stream::iter_ok::<_, io::Error>(iter::repeat(()));
            let local_to_dst = iter.fold((local_reader, dst_writer), move |(reader, writer), _|{
                let encrypter = Arc::clone(&encrypter_inner1);
                io::read(reader, vec![0; 102400])
                .and_then(move |(reader, buf, len)| {
                    println!("read {} bytes from local server;", len);
                    if len == 0 {
                        Either::A(future::err(io::Error::new(io::ErrorKind::BrokenPipe, "remote connection closed!")))
                    } else {
                        let mut data = encrypter.lock().unwrap().decode(&buf[0..len]);
                        let data = match data[0] {
                            0x1 => {
                                data.split_off(7)
                            },
                            len => {
                                data.split_off(len as usize + 3)
                            }
                        };
                        Either::B(
                            io::write_all(writer, data)
                            .and_then(move |(writer, _)| {
                                Ok((reader, writer))
                            })
                        )
                    }
                })
            }).map(|_|()).map_err(|_|{
                println!("connection closed!");
            });

            let iter = stream::iter_ok::<_, io::Error>(iter::repeat(()));
            let dst_to_local = iter.fold((dst_reader, local_writer), move |(reader, writer), _| {
                let encrypter = Arc::clone(&encrypter_inner2);
                io::read(reader, vec![0; 102400])
                .and_then(move |(reader, buf, len)| {
                    // TODO 
                    println!("read {} bytes from dst site;", len);
                    if len == 0 {
                        Either::A(future::err(io::Error::new(io::ErrorKind::BrokenPipe, "remote connection closed!")))
                    } else {
                        let data = encrypter.lock().unwrap().encode(&buf[0..len]);
                        Either::B(
                            io::write_all(writer, data)
                            .and_then(move |(writer, _)| {
                                Ok((reader, writer))
                            })
                        )
                    }
                })
            }).map(|_|()).map_err(|_|{
                println!("connection closed!");
            });

            let data_forward = local_to_dst.select(dst_to_local);
            data_forward.then(|_|{
                println!("data forward end!");
                Ok(())
            })

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
