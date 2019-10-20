#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
use std::process;
use structopt::StructOpt;

mod utils;
mod server;
mod client;
mod encoder;
mod server_backend_tun;
mod client_frontend_tun;
mod server_backend_socks5;
mod client_frontend_socks5;

use encoder::EncoderMethods;

#[derive(StructOpt, Debug)]
#[structopt(name = "TT", about = "TT, The Tunnel")]
enum Opt {
    #[structopt(name = "server", about = "TT, The Tunnel, server side")]
    server {
        #[structopt(short = "l", long = "listen", default_value = "0.0.0.0")]
        LISTEN_ADDR: String,
        #[structopt(short = "k", long = "key")]
        KEY: String,
        #[structopt(short, long, default_value = "chacha20-poly1305")]
        METHODS: String,
        #[structopt(short, long = "port-range", default_value = "1024-65535")]
        RANGE: String,
        #[structopt(long, default_value = "4096")]
        BUFFER_SIZE: usize,
        #[structopt(long)]
        TUN_IP: Option<String>,

    },
    #[structopt(name = "client", about = "TT, The Tunnel, client side")]
    client {
        #[structopt(short, long)]
        SERVER: String,
        #[structopt(short = "l", long = "listen", default_value = "127.0.0.1:1080")]
        LISTEN_ADDR: String,
        #[structopt(short = "k", long = "key")]
        KEY: String,
        #[structopt(short, long, default_value = "chacha20-poly1305")]
        METHODS: String,
        #[structopt(short, long = "port-range", default_value = "1024-65535")]
        RANGE: String,
        #[structopt(long, default_value = "4096")]
        BUFFER_SIZE: usize,
        #[structopt(long, conflicts_with = "listen-addr")]
        TUN_IP: Option<String>,
    }
}

fn main() {
    match Opt::from_args() {
        Opt::server{ LISTEN_ADDR, KEY, METHODS, RANGE, BUFFER_SIZE, TUN_IP } => {
            assert!(BUFFER_SIZE<=65536);
            let RANGE: Vec<&str> = RANGE.split("-").collect();
            let PORT_RANGE_START = RANGE[0].parse::<u32>().unwrap();
            let PORT_RANGE_END = RANGE[1].parse::<u32>().unwrap();
            let KEY:&'static str = Box::leak(KEY.into_boxed_str());
            let LISTEN_ADDR:&'static str = Box::leak(LISTEN_ADDR.into_boxed_str());
            let METHODS = match METHODS.as_ref() {
                "aes-256-gcm" => &EncoderMethods::AES256,
                "chacha20-poly1305" => &EncoderMethods::ChaCha20,
                _ => {
                    eprintln!("Methods [{}] not supported!", METHODS);
                    process::exit(-1);
                }
            };
            server::run(KEY, METHODS, LISTEN_ADDR, PORT_RANGE_START, PORT_RANGE_END, BUFFER_SIZE, TUN_IP);
        },
        Opt::client{ SERVER, LISTEN_ADDR, KEY, METHODS, RANGE, BUFFER_SIZE, TUN_IP } => {
            assert!(BUFFER_SIZE<=65536);
            let RANGE: Vec<&str> = RANGE.split("-").collect();
            let PORT_RANGE_START = RANGE[0].parse::<u32>().unwrap();
            let PORT_RANGE_END = RANGE[1].parse::<u32>().unwrap();
            let KEY:&'static str = Box::leak(KEY.into_boxed_str());
            let SERVER_ADDR:&'static str = Box::leak(SERVER.into_boxed_str());
            let LISTEN_ADDR:&'static str = Box::leak(LISTEN_ADDR.into_boxed_str());
            let METHODS = match METHODS.as_ref() {
                "aes-256-gcm" => &EncoderMethods::AES256,
                "chacha20-poly1305" => &EncoderMethods::ChaCha20,
                _ => {
                    eprintln!("Methods [{}] not supported!", METHODS);
                    process::exit(-1);
                }
            };
            client::run(KEY, METHODS, SERVER_ADDR, LISTEN_ADDR, PORT_RANGE_START, PORT_RANGE_END, BUFFER_SIZE, TUN_IP);
        },
    }
}
