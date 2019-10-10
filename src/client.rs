#![allow(non_snake_case)]

use std::time;
use std::error::Error;
use std::net::{TcpStream, SocketAddr, ToSocketAddrs};
use crate::utils;
use crate::encoder::{Encoder, EncoderMethods};
use crate::encoder::aes256gcm::AES256GCM;
use crate::encoder::chacha20poly1305::ChaCha20;
pub fn get_stream(KEY:&'static str, METHOD:&'static EncoderMethods, 
    SERVER_ADDR:&'static str, PORT_RANGE_START:u32, PORT_RANGE_END:u32) 
                    -> Result<(TcpStream, Encoder), Box::<dyn Error>> {
    let otp = utils::get_otp(KEY, utils::get_secs_now()/60);
    let port = utils::get_port(otp, PORT_RANGE_START, PORT_RANGE_END);
    let server = format!("{}:{}", SERVER_ADDR, port);
    println!("Using port: [{}]", port);
    let server:Vec<SocketAddr> = server.to_socket_addrs()?.collect();

    let encoder = match METHOD {
        EncoderMethods::AES256 => Encoder::AES256(AES256GCM::new(KEY, otp)),
        EncoderMethods::ChaCha20 => Encoder::ChaCha20(ChaCha20::new(KEY, otp)),
    };

    Ok((
        // if we want to use connect_timeout here, we can only use one server
        TcpStream::connect_timeout(&server[0], time::Duration::from_secs(5))?,
        encoder
    ))
}
