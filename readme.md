## Introduction

I was trying to write a Rust version of shadowsocks for practice after learning Rust.

This project implements a simplified shadowsocks model based on crate tokio, trust_dns and openssl.

So far I've finished most of it, including a local server and a remote server. Communication between then is partially encrypted. And a GUI for local server is on my schedule, but probably I don't have enough time to complete.

* 1.24: rewrite this project in tokio 0.2.x, futures 0.3.x and async/await;

## Dependencies

tokio = "0.2.10"

futures = "0.3"

openssl = "0.10" // In Windows you should install OpenSSL-win and add it to Path ($env:OPENSSL_DIR)


## Structure

1. ss_local: local server (listening on 7962 port)
2. ss_server: remote server (listening on 9002 port)

## Test

Just clone this repo and then in console:

```bash
cargo run -p ss_local
cargo run -p ss_server
```

You can change the source code to customize your application, including port, DNS address, etc. I haven't provided configuration method yet(maybe later...).

Cause shadowsocks is based on Sock5 proxy, you can use Chrome extension [TunnelSwitch](https://chrome.google.com/webstore/detail/tunnelswitch/nfpphleklkamlblagdkbkomjmaedanoh) to provide socks5 client in Chrome (set proxy server as 127.0.0.1:7962).

As for actual use, more tests should be done.

Currently this project is just a practice for Rust programming.