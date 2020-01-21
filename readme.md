## Introduction

I was trying to write a Rust version of shadowsocks for practice after learning Rust.

This project implements a simplified shadowsocks model based on crate tokio, trust_dns and openssl.

So far I've finished most of it, including a local server and a remote server. Communication between then is partially encrypted. And a GUI for local server is on my schedule, but probably I don't have enough time to complete.

**NOTE: Currently I'm rewriting it with the new tokio 0.2.0 and async/await feature**

## Dependencies

tokio = "0.2.0"

futures = "0.3"

openssl = "0.10" // In Windows you should install OpenSSL-win and add it to Path

trust-dns = "0.16"

## Structure

1. ss_local: local server (listening on 7962 port)
2. ss_server: remote server (listening on 9002 port)
3. ss_gui: not implemented yet...

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