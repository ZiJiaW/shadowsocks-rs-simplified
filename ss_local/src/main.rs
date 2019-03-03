extern crate tokio;
#[macro_use]
extern crate futures;
extern crate bytes;

use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::prelude::*;
use futures::sync::mpsc;
use futures::future::{self, Either};
use bytes::{BytesMut, Bytes, BufMut};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

const SS_SERVER_ADDR: &'static str = "127.0.0.1:9002";

fn main()
{
    let addr = "127.0.0.1:7962".parse().unwrap();
    let listener = TcpListener::bind(&addr).unwrap();
    let server = listener.incoming().for_each(|socket| {
        process(socket);
        Ok(())
    })
    .map_err(|e| {
        println!("Error happened: {:?}", e);
    });
    println!("Server listening on {:?}", addr);
    tokio::run(server);
}

mod Socks5 {
    pub const VER: u8 = 0x5;
    pub const AUTH: u8 = 0x0;
}

fn hand_shake(socket: TcpStream) -> impl Future<Item = TcpStream, Error = io::Error>
{
    io::read_exact(socket, vec![0u8])
    .and_then(|(socket, buf)| {
        if buf[0] != Socks5::VER {
            println!("addr {:?} socks version is {}!", socket.peer_addr().unwrap(), buf[0]);
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Wrong version!"));
        } else {
            Ok(socket)
        }
    })
    .and_then(|socket| {
        io::read_exact(socket, vec![0u8])
        .and_then(|(socket, buf)| {
            let len = buf[0];
            Ok((socket, len))
        })
    })
    .and_then(|(socket, len)| {
        io::read_exact(socket, vec![0u8, len])
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

//fn connect()

// Main processing logic
fn process(socket: TcpStream)
{
    let handler = hand_shake(socket)
    .map(|_|{})
    .map_err(|_|{});
    tokio::spawn(handler);
}
