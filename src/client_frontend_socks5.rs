#![allow(non_snake_case)]
#![allow(unused_must_use)]
use std::net;
use std::thread;
use crate::client;
use std::io::prelude::*;
use crate::encoder::EncoderMethods;

pub fn run(KEY:&'static str, METHOD:&'static EncoderMethods, SERVER_ADDR:&'static str, 
    BIND_ADDR:&'static str, PORT_RANGE_START:u32, PORT_RANGE_END:u32, BUFFER_SIZE:usize) {

    let listener = match net::TcpListener::bind(BIND_ADDR){
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("Failed to bind [{}], {}", BIND_ADDR, err);
            return;
        }
    };
    for stream in listener.incoming() {
        thread::spawn(move||{
            handle_connection(stream.unwrap(),
                KEY, METHOD, SERVER_ADDR, 
                PORT_RANGE_START, PORT_RANGE_END, BUFFER_SIZE);
        });
    }
}

pub fn handle_connection(local_stream:net::TcpStream, KEY:&'static str, METHOD:&'static EncoderMethods,
                        SERVER_ADDR:&'static str, PORT_RANGE_START:u32, 
                        PORT_RANGE_END:u32, BUFFER_SIZE:usize,) {
    let (upstream, encoder) = match client::get_stream(KEY, METHOD, SERVER_ADDR, 
                                            PORT_RANGE_START, PORT_RANGE_END) {
        Ok((upstream, encoder)) => (upstream, encoder),
        Err(err) => {
            eprintln!("Error: Failed to connect to server, {}", err);
            return;
        }
    };
    local_stream.set_nodelay(true);
    upstream.set_nodelay(true);

    let mut upstream_read = upstream.try_clone().unwrap();
    let mut upstream_write = upstream.try_clone().unwrap();
    let mut local_stream_read = local_stream.try_clone().unwrap();
    let mut local_stream_write = local_stream.try_clone().unwrap();
    let decoder = encoder.clone();

    // download stream
    let _download = thread::spawn(move || {
        //std::io::copy(&mut upstream_read, &mut local_stream_write);
        let mut index: usize = 0;
        let mut offset:i32;
        let mut buf = vec![0u8; BUFFER_SIZE];
        loop {
            index += match upstream_read.read(&mut buf[index..]) {
                Ok(read_size) if read_size > 0 => read_size,
                _ => {
                    //eprintln!("upstream read failed");
                    upstream_read.shutdown(net::Shutdown::Both);
                    local_stream_write.shutdown(net::Shutdown::Both);
                    // #TODO
                    // 1. distinguish from server port close, something like a packet "FFFF"..
                    // 2. upstream status shall be handled by client.rs, encode/decode included
                    break;
                }
            };
            offset = 0;
            loop {
                let (data_len, _offset) = decoder.decode(&mut buf[offset as usize..index]);
                if data_len > 0 {
                    offset += _offset;
                    match local_stream_write.write(&buf[offset as usize- data_len .. offset as usize]) {
                        Ok(_) => (),
                        _ => {
                            //eprintln!("local_stream write failed");
                            upstream_read.shutdown(net::Shutdown::Both);
                            local_stream_write.shutdown(net::Shutdown::Both);
                            break;
                        }
                    };
                    if (index - offset as usize) < (1 + 12 + 2 + 16) {
                        break;  // definitely not enough data to decode
                    }
                }
                else if _offset == -1 {
                     eprintln!("download stream decode error!");
                     offset = -1;
                     break;
                }
                else { break; } // decrypted_size ==0 && offset == 0: not enough data to decode
            }
            if offset == -1 {break;}
            buf.copy_within(offset as usize .. index, 0);
            index = index - (offset as usize);
        }
        //println!("Download stream exited...");
    });

    // upload stream
    let _upload = thread::spawn(move || {
        //std::io::copy(&mut local_stream_read, &mut upstream_write);
        let mut index: usize;
        let mut buf = vec![0u8;  BUFFER_SIZE];
        loop {
            // from docs, size = 0 means EOF,
            // maybe we don't need to worry about TCP Keepalive here.
            index = match local_stream_read.read(&mut buf[..BUFFER_SIZE-60]) {
                Ok(read_size) if read_size > 0 => read_size,
                _ => {
                    //eprintln!("local_stream read failed");
                    upstream_write.shutdown(net::Shutdown::Both);
                    local_stream_read.shutdown(net::Shutdown::Both);
                    break;
                }
            };
            index = encoder.encode(&mut buf, index);
            match upstream_write.write(&buf[..index]) {
                Ok(_) => (),
                _ => {
                    //eprintln!("upstream write failed");
                    upstream_write.shutdown(net::Shutdown::Both);
                    break;
                }
            };
        }
        //println!("Upload stream exited...");
    });
}
