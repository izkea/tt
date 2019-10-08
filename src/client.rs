#![allow(non_snake_case)]

use std::time;
use std::error::Error;
use std::net::{TcpStream, SocketAddr, ToSocketAddrs};
use crate::utils;
use crate::encoder::chacha20poly1305::Encoder;
pub fn get_stream(KEY:&'static str, SERVER_ADDR:&'static str, PORT_RANGE_START:u32, PORT_RANGE_END:u32) 
            -> Result<(TcpStream, Encoder), Box::<dyn Error>> {
    let otp = utils::get_otp(KEY, utils::get_secs_now()/60);
    let port = utils::get_port(otp, PORT_RANGE_START, PORT_RANGE_END);
    let server = format!("{}:{}", SERVER_ADDR, port);
    println!("Using port: [{}]", port);
    //Ok((net::TcpStream::connect(server)?, Encoder::new(KEY, otp)))

    let server:Vec<SocketAddr> = server.to_socket_addrs()?.collect();
    Ok((
        // if we want to use connect_timeout here, we can only use one server
        TcpStream::connect_timeout(&server[0], time::Duration::from_secs(5))?,
        Encoder::new(KEY, otp)
    ))
}
