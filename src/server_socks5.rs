#![allow(non_snake_case)]
#![allow(unused_must_use)]
use std::net;
use std::thread;
use std::sync::mpsc;
use std::error::Error;
use std::io::prelude::*;
use crate::encoder::{Encoder};
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr, ToSocketAddrs, TcpStream};

#[allow(unused_imports)]
use log::{trace, debug, info, warn, error, Level};

//pub fn handle_connection(&self, client_stream:net::TcpStream, encoder:Encoder) {
pub fn handle_connection(rx: mpsc::Receiver<(TcpStream, Encoder)>, BUFFER_SIZE:usize){
    for (client_stream, encoder) in rx {
        thread::spawn( move || do_handle_connection(client_stream, encoder, BUFFER_SIZE));
    }
}

pub fn do_handle_connection(client_stream:TcpStream, encoder: Encoder, BUFFER_SIZE: usize) {
    let _encoder = encoder.clone();
    let _client_stream = client_stream.try_clone().unwrap();
    let upstream = match simple_socks5_handshake(_client_stream, _encoder){
        Ok(stream) => stream,
        Err(_) => {client_stream.shutdown(net::Shutdown::Both); return;}
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
        debug!("Download stream exited...");
    });

    // upload stream
    let _upload = thread::spawn(move || {
        let mut index: usize = 0;
        let mut offset:  i32;
        let mut last_offset: i32 = 0;
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
                        Err(_) => {
                            offset = -2;
                            break;
                        }
                    };
                    if (index - offset as usize) < (1 + 12 + 2 + 16) {
                        break; // definitely not enough data to decode
                    }
                }
                else if data_len == 0 && _offset == -1 {
                    error!("Packet decode error from: [{}]", client_stream_read.peer_addr().unwrap());
                    if last_offset == -1 {
                        offset = -2;
                    }
                    else {
                        offset = -1;
                    }
                    break;
                }
                else { break; } // decrypted_size ==0 && offset != -1: not enough data to decode
            }
            if offset > 0 {
                buf.copy_within(offset as usize .. index, 0);
                index = index - (offset as usize);
                last_offset = 0;
            }
            else if offset == -1 {
                last_offset = -1;
            }
            else if offset == -2 {
                break;
            }
        }
        client_stream_read.shutdown(net::Shutdown::Both);
        upstream_write.shutdown(net::Shutdown::Both);
        debug!("Upload stream exited...");
    });
}

pub fn simple_socks5_handshake(mut stream: TcpStream, encoder:Encoder) -> Result<TcpStream, Box<dyn Error>>{
    let mut buf = [0u8; 512];
    stream.read(&mut buf)?;
    let (data_len, offset) = encoder.decode(&mut buf);
    if data_len == 0 || buf[offset as usize - data_len] != 0x05 {
        return Err("not socks5".into());            // not socks5
    }

    buf[..2].copy_from_slice(&[0x05, 0x00]);
    let data_len = encoder.encode(&mut buf, 2);
    stream.write(&buf[..data_len])?;

    stream.read(&mut buf)?;
    let (data_len, offset) = encoder.decode(&mut buf);
    if data_len == 0 || buf[offset as usize - data_len + 1] != 0x01 {
        return Err("not CONNECT".into());           // not CONNECT
    }

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
            domain.to_socket_addrs()?.collect()
        },
        0x04 => {                                   // ipv6 address
            let buf = (2..10).map(|x| {
                (u16::from(_buf[(x * 2)]) << 8) | u16::from(_buf[(x * 2) + 1])
            }).collect::<Vec<u16>>();
            vec![ SocketAddr::from( SocketAddrV6::new( Ipv6Addr::new(
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]), port, 0, 0)
            )]
        },
        _ => return Err("failed to parse address".into()),
    };

    match TcpStream::connect(&addr[..]){
        Ok(upstream) => {
            buf[..10].copy_from_slice(&[0x5, 0x0, 0x0, 0x1, 0x7f, 0x0, 0x0, 0x1, 0x0, 0x0]);
            let data_len = encoder.encode(&mut buf, 10);
            match stream.write(&buf[..data_len]) {
                Ok(_) => return Ok(upstream),
                Err(_) => {
                    upstream.shutdown(net::Shutdown::Both);
                    return Err("client write failed".into());
                }
            };
        },
        Err(_) => {
            buf[..2].copy_from_slice(&[0x05, 0x01]);
            let data_len = encoder.encode(&mut buf, 2);
            stream.write(&buf[..data_len])?;
            return Err("upstream connect failed".into());
        }
    }
}
