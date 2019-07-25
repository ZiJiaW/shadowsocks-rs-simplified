## Introduction

I was trying to write a Rust version of shadowsocks for practice after learning Rust.

This project implements a simplified shadowsocks model based on crate tokio, trust_dns and openssl.

So far I've finished most of it, including a local server and a remote server. Communication between then is partially encrypted. And a GUI for local server is on my schedule, but probably I don't have enough time to complete.

## Dependencies

tokio = "0.1"

futures = "0.1"

openssl = "0.10" // In Windows you should install OpenSSL-win and add it to Path

trust-dns = "0.16"

## Structure

1. ss_local: local server
2. ss_server: remote server
3. ss_gui: not implemented yet...

## Test

Just clone this repo and then in console:

1. cargo run -p ss_local // listen on 7962 port
2. cargo run -p ss_server// listen on 9002 port

You can change the source code to customize your application, including port, DNS address, etc. I haven't provided configuration method yet(maybe later...).

Cause shadowsocks proxy is based on Sock5, you can use Chrome extension [TunnelSwitch](https://chrome.google.com/webstore/detail/tunnelswitch/nfpphleklkamlblagdkbkomjmaedanoh) to provide socks5 proxy in Chrome (set proxy server as 127.0
.0.1:7962).

As for actual use, more tests should be done. 

Currently this project is just a practice for Rust programming.