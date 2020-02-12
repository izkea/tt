#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
extern crate log;
extern crate structopt;

use std::process;
use std::fs::File;
use std::io::Write;
use structopt::StructOpt;
#[allow(unused_imports)]
use log::{trace, debug, info, warn, error, Level};

mod utils;
mod server;
mod client;
mod encoder;
#[cfg(not(target_os = "windows"))]
mod server_tun;
#[cfg(not(target_os = "windows"))]
mod client_tun;
mod server_socks5;
mod client_socks5;

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
        #[structopt(long, default_value = "1440")]
        MTU: usize,
        #[structopt(long)]
        TUN_IP: Option<String>,
        #[structopt(long="no-port-jump-on-tun-mode")]
        NO_PORT_JUMP: bool,
        #[structopt(short, long)]
        VERBOSE: bool,
        #[structopt(long)]
        PID: Option<String>,
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
        #[structopt(long, default_value = "1440")]
        MTU: usize,
        #[structopt(long, conflicts_with = "listen-addr")]
        TUN_IP: Option<String>,
        #[structopt(short, long)]
        VERBOSE: bool,
        #[structopt(long)]
        PID: Option<String>,
    }
}

fn main() {
    utils::my_log::init_with_level(Level::Debug).unwrap();
    match Opt::from_args() {
        Opt::server{ LISTEN_ADDR, KEY, METHODS, RANGE, MTU, TUN_IP, NO_PORT_JUMP, VERBOSE, PID } => {
            write_pid(PID);
            set_verbose(VERBOSE);
            assert!(MTU<=65536);
            let RANGE: Vec<&str> = RANGE.split("-").collect();
            let BUFFER_SIZE = if MTU > (4096 - 60) { MTU + 60 } else { 4096 };
            let PORT_RANGE_START = RANGE[0].parse::<u32>().unwrap();
            let PORT_RANGE_END = RANGE[1].parse::<u32>().unwrap();
            let KEY:&'static str = Box::leak(KEY.into_boxed_str());
            let LISTEN_ADDR:&'static str = Box::leak(LISTEN_ADDR.into_boxed_str());
            let METHODS = match METHODS.as_ref() {
                "aes-256-gcm" => &EncoderMethods::AES256,
                "chacha20-poly1305" => &EncoderMethods::ChaCha20,
                _ => {
                    error!("Methods [{}] not supported!", METHODS);
                    process::exit(-1);
                }
            };
            server::run(KEY, METHODS, LISTEN_ADDR, PORT_RANGE_START, PORT_RANGE_END, BUFFER_SIZE, TUN_IP, MTU, NO_PORT_JUMP);
        },
        Opt::client{ SERVER, LISTEN_ADDR, KEY, METHODS, RANGE, MTU, TUN_IP, VERBOSE, PID } => {
            write_pid(PID);
            set_verbose(VERBOSE);
            assert!(MTU<=65536);
            let RANGE: Vec<&str> = RANGE.split("-").collect();
            let BUFFER_SIZE = if MTU > (4096 - 60) { MTU + 60 } else { 4096 };
            let PORT_RANGE_START = RANGE[0].parse::<u32>().unwrap();
            let PORT_RANGE_END = RANGE[1].parse::<u32>().unwrap();
            let KEY:&'static str = Box::leak(KEY.into_boxed_str());
            let SERVER_ADDR:&'static str = Box::leak(SERVER.into_boxed_str());
            let LISTEN_ADDR:&'static str = Box::leak(LISTEN_ADDR.into_boxed_str());
            let METHODS = match METHODS.as_ref() {
                "aes-256-gcm" => &EncoderMethods::AES256,
                "chacha20-poly1305" => &EncoderMethods::ChaCha20,
                _ => {
                    error!("Methods [{}] not supported!", METHODS);
                    process::exit(-1);
                }
            };
            client::run(KEY, METHODS, SERVER_ADDR, LISTEN_ADDR, PORT_RANGE_START, PORT_RANGE_END, BUFFER_SIZE, TUN_IP, MTU);
        },
    }
}

fn set_verbose(VERBOSE :bool) {
    if !VERBOSE {
        log::set_max_level(Level::Info.to_level_filter());
    }
//    debug!("verbose output: on");
}
fn write_pid(PID: Option<String>) {
    info!("PID is {}", process::id());
    match PID{
        Some(pid) => {
            let data = format!("{}", process::id());
            let mut f = File::create(pid).expect("Unable to create file");
            f.write_all(data.as_bytes()).expect("Unable to write data");
        },
        _ => {}
    }
    
}
