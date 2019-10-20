#![allow(non_snake_case)]

use std::net;
use std::time;
use std::thread;
use std::sync::{Arc, Mutex, mpsc};

use crate::utils;
use crate::server_backend_tun;
use crate::server_backend_socks5;
use crate::encoder::{Encoder, EncoderMethods};
use crate::encoder::aes256gcm::AES256GCM;
use crate::encoder::chacha20poly1305::ChaCha20;


pub fn run(KEY:&'static str, METHOD:&'static EncoderMethods, BIND_ADDR:&'static str, 
            PORT_START:u32, PORT_END:u32, BUFFER_SIZE:usize, TUN_IP: Option<String>) {

    let (tx, rx) = mpsc::channel();
    let tun = match TUN_IP{
        Some(tun_ip) => {
            thread::spawn( move || server_backend_tun::handle_connection(rx, BUFFER_SIZE, &tun_ip));
            true
        },
        None  => {
            thread::spawn( move || server_backend_socks5::handle_connection(rx, BUFFER_SIZE));
            false
        }
    };

    let time_now = utils::get_secs_now() / 60;
    let _tx1 = tx.clone();
    let _tx2 = tx.clone();
    let _tx3 = tx.clone();
    thread::spawn( move || start_listener(_tx1, KEY, METHOD, BIND_ADDR, PORT_START, PORT_END, time_now - 1, tun));
    thread::spawn( move || start_listener(_tx2, KEY, METHOD, BIND_ADDR, PORT_START, PORT_END, time_now    , tun));
    thread::spawn( move || start_listener(_tx3, KEY, METHOD, BIND_ADDR, PORT_START, PORT_END, time_now + 1, tun));

    loop {
        thread::sleep(time::Duration::from_secs(2));
        let time_now = utils::get_secs_now();
        if time_now % 60 >= 2 { continue; };  // once a minute
        let _tx = tx.clone();
        thread::spawn( move || start_listener(
            _tx, KEY, METHOD, BIND_ADDR, PORT_START, PORT_END, utils::get_secs_now()/60 + 1, tun)
        );
    }

    /*
    let mut sched = JobScheduler::new();
    sched.add(Job::new("0 * * * * *".parse().unwrap(), || {
        thread::spawn( move || start_listener(
                KEY, BIND_ADDR, PORT_RANGE_START, PORT_RANGE_END, BUFFER_SIZE, utils::get_secs_now()/60 + 1));
    }));
    loop {
        sched.tick();
        std::thread::sleep(time::Duration::from_millis(500));
    }
    */
}

fn start_listener(tx: mpsc::Sender<(net::TcpStream, Encoder)>, KEY:&'static str, METHOD:&EncoderMethods, 
    BIND_ADDR:&'static str, PORT_RANGE_START:u32, PORT_RANGE_END:u32, time_start:u64, tun: bool) {
    let otp = utils::get_otp(KEY, time_start);
    let port = utils::get_port(otp, PORT_RANGE_START, PORT_RANGE_END);
    let lifetime = utils::get_lifetime(otp);
    let encoder = match METHOD {
        EncoderMethods::AES256 => Encoder::AES256(AES256GCM::new(KEY, otp)),
        EncoderMethods::ChaCha20 => Encoder::ChaCha20(ChaCha20::new(KEY, otp)),
    };
    println!("Open port : [{}], lifetime: [{}]", port, lifetime);

    let streams = Arc::new(Mutex::new(Vec::new())); 
    let flag_stop = Arc::new(Mutex::new(false));
    let listener = match net::TcpListener::bind(format!("{}:{}", BIND_ADDR, port)) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("Error binding port: [{}], {}", port, err);
            return
        }
    };

    /*  1. not using JobScheduler, cause it adds too much stupid code here.
     *  2. can't find a proper way to drop listener inside _timer_thread, 
     *     tried: Box + raw pointer, Arc<Mutex<listener>>...
     *  3. So we use 'flag_stop' to transfer the status, and connect to the port to break
     *     the main thread from listener.incoming()
     */
    let _streams = Arc::clone(&streams);
    let _flag_stop = Arc::clone(&flag_stop);
    let _timer_thread = thread::spawn(move || {
        loop {
            thread::sleep(time::Duration::from_secs(3));
            let time_now = utils::get_secs_now();
            if time_now % 60 >= 3 || time_now/60 < time_start { continue; };  // once a minute
            let time_diff = (time_now / 60 - time_start) as u8;
            if time_diff >= lifetime || time_diff > 2 && _streams.lock().unwrap().len() == 0 {
                *_flag_stop.lock().unwrap() = true;
                drop(_streams);
                drop(_flag_stop);
                net::TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
                break;
            }
        }
    });


    for stream in listener.incoming() {
        if *flag_stop.lock().unwrap() { 
            drop(listener); 
            break; 
        };
        let stream = match stream {
            Ok(stream) => stream,
            Err(_) => continue                      // try not to panic on error "Too many open files"
        };
        let _stream = match stream.try_clone() {
            Ok(_stream) => _stream,
            Err(_) => continue,                     // same as above
        };
        let _encoder = encoder.clone();
        tx.send((_stream, _encoder)).unwrap();
        streams.lock().unwrap().push(stream);
    }
    println!("Close port: [{}], lifetime: [{}]", port, lifetime);
    
    // #TODO If we kill all the existing streams, then the client has to establish a new one to
    // resume downloading process. Also, if we kill streams at the very first seconeds of each
    // minute, this seems to be a traffic pattern.
    // so we disable it for socks5 mode, as client_frontend_socks5 will just drop the connection.
    
    if tun {
        let lock = Arc::try_unwrap(streams).expect("Error: lock still has multiple owners");
        let streams = lock.into_inner().expect("Error: mutex cannot be locked");
        for stream in streams {
            stream.shutdown(net::Shutdown::Both).unwrap_or_else(|_err|());
            drop(stream)
        }
    }
    else {
    }
}
