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

/// Shorthand for the transmit half of the message channel.
type Tx = mpsc::UnboundedSender<Bytes>;

/// Shorthand for the receive half of the message channel.
type Rx = mpsc::UnboundedReceiver<Bytes>;

struct Shared {
    peers: HashMap<SocketAddr, Tx>,
}
impl Shared {
    /// Create a new, empty, instance of `Shared`.
    fn new() -> Self {
        Shared {
            peers: HashMap::new(),
        }
    }
}

fn main()
{
    let addr = "127.0.0.1:6142".parse().unwrap();
    let listener = TcpListener::bind(&addr).unwrap();
    let state = Arc::new(Mutex::new(Shared::new()));

    let server = listener.incoming().for_each(move |socket| {
        process(socket, state.clone());
        Ok(())
    })
    .map_err(|err| {
        // Handle error by printing to STDOUT.
        println!("accept error = {:?}", err);
    });

    println!("server running on localhost:6142");
    tokio::run(server);
}

struct Lines {
    socket: TcpStream,
    rd: BytesMut,// data read from socket
    wr: BytesMut,// data to be written to socket
}

impl Lines {
    fn new(socket: TcpStream) -> Self
    {
        Lines {
            socket, rd: BytesMut::new(), wr: BytesMut::new(),
        }
    }

    fn fill_read_buf(&mut self) -> Poll<(), io::Error>
    {
        loop {// read to rd until there's nothing to read
            self.rd.reserve(1024);
            let n = try_ready!(self.socket.read_buf(&mut self.rd));
            if n == 0 {
                return Ok(Async::Ready(()));
            }
        }
    }

    fn buffer(&mut self, line: &[u8])
    {
        self.wr.reserve(line.len());
        self.wr.put(line);
    }

    fn poll_flush(&mut self) -> Poll<(), io::Error>
    {
        while !self.wr.is_empty()
        {
            let n = try_ready!(self.socket.poll_write(&self.wr));
            assert!(n > 0);// it'll never happen as long as wr is not empty
            self.wr.split_to(n);// discard written content
        }
        Ok(Async::Ready(()))// wr has all been written to socket
    }
}

impl Stream for Lines {
    type Item = BytesMut;
    type Error = io::Error;
    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error>
    {
        let sock_closed = self.fill_read_buf()?.is_ready();
        let pos = self.rd.windows(2).position(|bytes| bytes == b"\r\n");
        if let Some(pos) = pos
        {
            let mut line = self.rd.split_to(pos + 2);
            line.split_off(pos);// drop \r\n, get the rest of line
            return Ok(Async::Ready(Some(line)));
        }
        // ready but nothing to read, means closed, this stream has no further line
        if sock_closed {
            Ok(Async::Ready(None))
        } else {
            Ok(Async::NotReady)
        }
    }
}

struct Peer {
    name: BytesMut,// peer's name
    lines: Lines,// wrapped socket
    state: Arc<Mutex<Shared>>,// 
    rx: Rx,// reciever
    addr: SocketAddr,// peer address
}

impl Peer {
    fn new(name: BytesMut, state: Arc<Mutex<Shared>>, lines: Lines) -> Peer
    {
        let addr = lines.socket.peer_addr().unwrap();
        let (tx, rx) = mpsc::unbounded();
        state.lock().unwrap().peers.insert(addr, tx);// add sender and address into the shared map
        Peer {
            name, lines, state, rx, addr,
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.state.lock().unwrap().peers.remove(&self.addr);
    }
}

impl Future for Peer {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error>
    {
        // recieve all messages from peers
        loop {
            match self.rx.poll().unwrap() {
                Async::Ready(Some(v)) => {
                    self.lines.buffer(&v);
                }
                _ => break,
            }
        }
        // write to socket
        let _ = self.lines.poll_flush()?;
        //-----------now read this own socket------------------
        // read new lines
        while let Async::Ready(line) = self.lines.poll()?
        {
            println!("Received new line from {:?} : {:?}", self.name, line);
            if let Some(message) = line
            {
                let mut line = self.name.clone();
                line.reserve(message.len()+5);
                line.put(":");
                line.put(&message);
                line.put("\r\n");
                let line = line.freeze();// make it immutable for zero cost cloning
                //------now send this line to all peers--------------
                for (addr, tx) in &self.state.lock().unwrap().peers
                {
                    if *addr != self.addr {
                        tx.unbounded_send(line.clone()).unwrap();
                    }
                }

            }
            else {// line is None, which mean socket has been closed
                return Ok(Async::Ready(()));
            }
        }
        Ok(Async::NotReady)// got inner NotReady
    }
}

fn process(socket: TcpStream, state: Arc<Mutex<Shared>>)
{
    let lines = Lines::new(socket);
    let connection = lines.into_future()// it split the stream as (first line, rest lines)
    .map_err(|(e, _)| e)
    .and_then(|(name, lines)|{
        let name = match name {
            Some(name) => name,
            None => {
                //connection has been closed without sending any data
                return Either::A(future::ok(()));// just return ok
            }
        };
        // message passing logic
        println!("{:?} is joining the chat!", name);
        let peer = Peer::new(name, state, lines);
        Either::B(peer)
    })
    .map_err(|e| {
        println!("connection error encountered: {:?}", e);
    });
    tokio::spawn(connection);
}