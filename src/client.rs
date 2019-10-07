#![allow(non_snake_case)]

use std::io;
use std::net;
use crate::utils;
use crate::encoder::chacha20poly1305::Encoder;
pub fn get_stream(KEY:&'static str, SERVER_ADDR:&'static str, PORT_RANGE_START:u32, PORT_RANGE_END:u32) 
            -> (io::Result<net::TcpStream>, Encoder) {
    let otp = utils::get_otp(KEY, utils::get_secs_now()/60);
    let port = utils::get_port(otp, PORT_RANGE_START, PORT_RANGE_END);
    println!("Using port: [{}]", port);
    (net::TcpStream::connect(format!("{}:{}", SERVER_ADDR, port)), Encoder::new(KEY, otp))
}
