extern crate tokio;
extern crate futures;

use ss_local::Encypter;

use futures::future::{select};

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, lookup_host};

use std::sync::{Arc, Mutex, RwLock};
use std::net::{Ipv4Addr, IpAddr, SocketAddr};
use std::collections::HashMap;
use futures::FutureExt;


const PACKAGE_SIZE: usize = 8196;

async fn run(mut socket: TcpStream,
       encrypter: Arc<Mutex<Encypter>>,
       dns_map: Arc<RwLock<HashMap<String, IpAddr>>>) -> io::Result<()>
{
    let mut buf = vec![0u8; 1];
    socket.read_exact(&mut buf).await?;
    let mut dst: TcpStream = match buf[0] {
        0x1 => {
            let mut buf = vec![0u8; 6];
            socket.read_exact(&mut buf).await?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
            let dst_addr = SocketAddr::new(IpAddr::V4(ip), port);
            TcpStream::connect(&dst_addr).await?
        },
        length => {
            let length = length as usize;
            let mut buf = vec![0u8; length + 2];
            socket.read_exact(&mut buf).await?;
            let port = ((buf[length] as u16) << 8) | (buf[length + 1] as u16);
            let mut addr = String::from_utf8_lossy(&buf[0..length]).to_string();
            println!("connecting: {}", addr);
            if dns_map.read().unwrap().contains_key(&addr) {
                println!("address {} has been found", addr);
                let ip = dns_map.read().unwrap().get(&addr).unwrap().clone();
                let dst_addr = SocketAddr::new(ip, port);
                TcpStream::connect(&dst_addr).await?
            } else {
                addr = addr + ":" + &port.to_string();
                let mut dst_addrs = lookup_host(&addr).await?;
                let dst_addr = dst_addrs.next().unwrap();
                println!("saved address {} is {:?}", addr,  dst_addr.ip());
                dns_map.write().unwrap().insert(addr.clone(), dst_addr.ip());
                TcpStream::connect(&dst_addr).await?
            }
        }
    };

    let (mut local_reader, mut local_writer) = socket.split();
    let (mut dst_reader, mut dst_writer) = dst.split();

    let inner1 = encrypter.clone();
    let inner2 = encrypter.clone();

    let local_to_dst = async move {
        loop {
            let mut buf = vec![0u8; 2];
            if local_reader.read_exact(&mut buf).await.is_err() {
                break;
            }
            let len: usize = ((buf[1] as usize) << 8) | (buf[0] as usize);
            buf.resize(len, 0u8);

            if local_reader.read_exact(&mut buf).await.is_err() {
                break;
            }
            let data = inner1.lock().unwrap().decode(&buf[0..len]);
            if dst_writer.write_all(&data).await.is_err() {
                break;
            }
        }
    };

    let dst_to_local = async move {
        loop {
            let mut buf = vec![0u8; PACKAGE_SIZE];
            match dst_reader.read(&mut buf).await {
                Ok(len) => {
                    if len == 0 {
                        break;
                    }
                    let mut data = inner2.lock().unwrap().encode(&buf[0..len]);
                    let len = data.len().to_le_bytes();
                    data.insert(0, len[1]);
                    data.insert(0, len[0]);
                    local_writer.write_all(&data).await.unwrap();
                },
                Err(_) => {
                    break;
                }
            }
        }
    };

    select(local_to_dst.boxed(), dst_to_local.boxed()).await;
    println!("connection close!");
    Ok(())
}

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:9002";
    let encrypter = Arc::new(Mutex::new(Encypter::new()));
    let dns_map = Arc::new(RwLock::new(HashMap::new()));
    let mut listener = TcpListener::bind(addr).await.unwrap();
    let server = async move {
        loop {
            match listener.accept().await {
                Ok((socket, _)) => {
                    tokio::spawn(
                        run(socket, encrypter.clone(), dns_map.clone())
                    );
                },
                Err(e) => println!("Error happened when accepting: {:?}", e),
            }
        }
    };
    println!("Remote server listening on {}", addr);
    server.await;
}