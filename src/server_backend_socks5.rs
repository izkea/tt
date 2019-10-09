#![allow(non_snake_case)]
#![allow(unused_must_use)]
use std::net;
use std::thread;
use merino::Merino;
use std::io::prelude::*;
use crate::encoder::chacha20poly1305::Encoder;

pub fn handle_connection(client_stream:net::TcpStream, encoder:Encoder, BUFFER_SIZE:usize) {
    let upstream = net::TcpStream::connect("127.10.80.1:10801").unwrap();
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
        let mut buf  = vec![0u8; BUFFER_SIZE - 50];
        let mut buf2 = vec![0u8; BUFFER_SIZE];
        loop {
            index = match upstream_read.read(&mut buf) {
                Ok(read_size) if read_size > 0 => read_size,
                _ => break
            };
            index = encoder.encode(&buf[..index], &mut buf2);
            match client_stream_write.write(&buf2[..index]) {
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
        let mut offset: i32;
        let mut buf  = vec![0u8; BUFFER_SIZE];
        let mut buf2 = vec![0u8; BUFFER_SIZE];
        loop {
            // from docs, size = 0 means EOF, 
            // maybe we don't need to worry about TCP Keepalive here.
            index += match client_stream_read.read(&mut buf[index..]) {
                Ok(read_size) if read_size > 0 => read_size,
                _ => break,
            };
            offset = 0;
            loop {
                let (decrypted_size, _offset) = decoder.decode(&buf[offset as usize..index], &mut buf2);
                if decrypted_size > 0 {
                    offset += _offset;
                    match upstream_write.write(&buf2[..decrypted_size]) {
                        Ok(_) => (),
                        Err(_) => break
                    };
                    if (index - offset as usize) < (1 + 2 + 16) {
                        break; // definitely not enough data to decode
                    }
                }
                else if _offset == -1 {
                    eprintln!("upload stream decode error!");
                }
                else { break; } // decrypted_size ==0 && offset == 0: not enough data to decode
            }
            buf.copy_within(offset as usize .. index, 0);
            index = index - (offset as usize);
        }
        client_stream_read.shutdown(net::Shutdown::Both);
        upstream_write.shutdown(net::Shutdown::Both);
        //println!("Upload stream exited...");
    });
}

pub fn run_merino() {
    let mut auth_methods: Vec<u8> = Vec::new();
    let auth_users:Vec<merino::User> = Vec::new();
    auth_methods.push(merino::AuthMethods::NoAuth as u8);

    let mut merino = Merino::new(10801, "127.10.80.1".to_string(), auth_methods, auth_users).unwrap();
    merino.serve().unwrap();
}

