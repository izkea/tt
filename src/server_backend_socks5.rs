#![allow(non_snake_case)]
#![allow(unused_must_use)]
use std::net;
use std::thread;
//use merino::Merino;
use std::io::prelude::*;
use crate::encoder::{Encoder};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr, ToSocketAddrs, TcpStream};


pub fn handle_connection(client_stream:net::TcpStream, encoder:Encoder, BUFFER_SIZE:usize) {
    let _encoder = encoder.clone();
    let _client_stream = client_stream.try_clone().unwrap();
    let upstream = match simple_socks5_handshake(_client_stream, _encoder){
        Some(stream) => stream,
        None => {client_stream.shutdown(net::Shutdown::Both); return}
    };

    upstream.set_nodelay(true);
    client_stream.set_nodelay(true);

    let mut upstream_read = upstream.try_clone().unwrap();
    let mut upstream_write = upstream.try_clone().unwrap();
    let mut client_stream_read = client_stream.try_clone().unwrap();
    let mut client_stream_write = client_stream.try_clone().unwrap();
    let decoder = encoder.clone();

    // download stream
    let _download = thread::spawn(move || {
        let mut index: usize;
        let mut buf  = vec![0u8; BUFFER_SIZE];
        loop {
            index = match upstream_read.read(&mut buf[..BUFFER_SIZE-60]) {
                Ok(read_size) if read_size > 0 => read_size,
                _ => break
            };
            index = encoder.encode(&mut buf, index);
            match client_stream_write.write(&buf[..index]) {
                Ok(_) => (),
                Err(_) => break
            };
        }
        upstream_read.shutdown(net::Shutdown::Both);
        client_stream_write.shutdown(net::Shutdown::Both);
        //println!("Download stream exited...");
    });

    // upload stream
    let _upload = thread::spawn(move || {
        let mut index: usize = 0;
        let mut offset:i32;
        let mut buf  = vec![0u8; BUFFER_SIZE];
        loop {
            // from docs, size = 0 means EOF, 
            // maybe we don't need to worry about TCP Keepalive here.
            index += match client_stream_read.read(&mut buf[index..]) {
                Ok(read_size) if read_size > 0 => read_size,
                _ => break,
            };
            offset = 0;
            loop {
                let (data_len, _offset) = decoder.decode(&mut buf[offset as usize..index]);
                if data_len > 0 {
                    offset += _offset;
                    match upstream_write.write(&buf[offset as usize - data_len .. offset as usize]) {
                        Ok(_) => (),
                        Err(_) => break
                    };
                    if (index - offset as usize) < (1 + 12 + 2 + 16) {
                        break; // definitely not enough data to decode
                    }
                }
                else if _offset == -1 {
                    eprintln!("upload stream decode error!");
                    offset = -1;
                    break;
                }
                else { break; } // decrypted_size ==0 && offset == 0: not enough data to decode
            }
            if offset == -1 {break;}
            buf.copy_within(offset as usize .. index, 0);
            index = index - (offset as usize);
        }
        client_stream_read.shutdown(net::Shutdown::Both);
        upstream_write.shutdown(net::Shutdown::Both);
        //println!("Upload stream exited...");
    });
}
/*
pub fn run_merino() {
    let mut auth_methods: Vec<u8> = Vec::new();
    let auth_users:Vec<merino::User> = Vec::new();
    auth_methods.push(merino::AuthMethods::NoAuth as u8);

    let mut merino = Merino::new(10801, "127.10.80.1".to_string(), auth_methods, auth_users).unwrap();
    merino.serve().unwrap();
}*/

fn simple_socks5_handshake(mut stream: TcpStream, encoder:Encoder) -> Option<TcpStream>{
    let mut buf = [0u8; 512];
    stream.read(&mut buf).unwrap();
    let (data_len, offset) = encoder.decode(&mut buf);
    if data_len == 0 || buf[offset as usize - data_len] != 0x05 {  return None }   // not sock5

    buf[..2].copy_from_slice(&[0x05, 0x00]);
    let data_len = encoder.encode(&mut buf, 2);
    stream.write(&buf[..data_len]).unwrap();

    stream.read(&mut buf).unwrap();
    let (data_len, offset) = encoder.decode(&mut buf);
    if data_len == 0 || buf[offset as usize - data_len + 1] != 0x01 {  return None }   // not CONNECT

    let _buf = &buf[offset as usize - data_len .. offset as usize];
    let port:u16 = ((_buf[data_len-2] as u16) << 8) | _buf[data_len-1] as u16;
    let addr = match _buf[3] {
        0x01 => {                                   // ipv4 address
            vec![SocketAddr::from(
                SocketAddrV4::new(Ipv4Addr::new(_buf[4], _buf[5], _buf[6], _buf[7]), port)
            )]
        },
        0x03 => {                                   // domain name
            let length = _buf[4] as usize;
            let mut domain = String::from_utf8_lossy(&_buf[5..length+5]).to_string();
            domain.push_str(&":");
            domain.push_str(&port.to_string());
            match domain.to_socket_addrs() {
                Ok(domain) => domain.collect(),
                Err(_)  => return None,
            }
        },
        0x04 => {                                   // ipv6 address
            let buf = (2..10).map(|x| {
                (u16::from(_buf[(x * 2)]) << 8) | u16::from(_buf[(x * 2) + 1])
            }).collect::<Vec<u16>>();
            vec![ SocketAddr::from( SocketAddrV6::new( Ipv6Addr::new(
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]), port, 0, 0)
            )]
        },
        _ => return None,
    };

    match TcpStream::connect(&addr[..]){
        Ok(upstream) => {
            buf[..10].copy_from_slice(&[0x5, 0x0, 0x0, 0x1, 0x7f, 0x0, 0x0, 0x1, 0x0, 0x0]);
            let data_len = encoder.encode(&mut buf, 10);
            stream.write(&buf[..data_len]).unwrap();
            Some(upstream)
        },
        Err(_) => {
            buf[..2].copy_from_slice(&[0x05, 0x01]);
            let data_len = encoder.encode(&mut buf, 2);
            stream.write(&buf[..data_len]).unwrap();
            return None
        }
    }
}
