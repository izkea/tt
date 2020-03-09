#![allow(non_snake_case)]
extern crate log;
extern crate lazy_static;

use std::net;
use std::time;
use std::thread;
use std::process;
use std::sync::{Arc, Mutex, mpsc};

use crate::utils;
use lazy_static::lazy_static;

#[allow(unused_imports)]
use log::{trace, debug, info, warn, error, Level};

#[cfg(not(target_os = "windows"))]
use crate::server_tun;
use crate::server_socks5;
use crate::encoder::{Encoder, EncoderMethods};
use crate::encoder::aes256gcm::AES256GCM;
use crate::encoder::chacha20poly1305::ChaCha20;

lazy_static! {
    static ref TUN_MODE:    Mutex<bool> = Mutex::new(false);
    static ref SOCKS5_MODE: Mutex<bool> = Mutex::new(false);
    static ref NO_PORT_JUMP:Mutex<bool> = Mutex::new(false);
}

pub fn run(KEY:&'static str, METHOD:&'static EncoderMethods, BIND_ADDR:&'static str, 
            PORT_START: u32, PORT_END: u32, BUFFER_SIZE: usize, TUN_IP: Option<String>,
            MTU: usize, _NO_PORT_JUMP: bool, _NO_SOCKS5: bool) {

    let (tx_tun, rx_tun) = mpsc::channel();
    let (tx_socks5, rx_socks5) = mpsc::channel();
    *NO_PORT_JUMP.lock().unwrap() = _NO_PORT_JUMP;

    *TUN_MODE.lock().unwrap() = match TUN_IP{
        Some(tun_ip) => {
            if cfg!(target_os = "windows") {
                error!("Error: tun mode does not support windows for now");
                process::exit(-1);
            }
            #[cfg(not(target_os = "windows"))]
            {
                info!("TT {}, Server (tun mode)", env!("CARGO_PKG_VERSION"));
                thread::spawn( move || server_tun::handle_connection(rx_tun, BUFFER_SIZE, &tun_ip, MTU));
            }
            true
        },
        None => false
    };

    *SOCKS5_MODE.lock().unwrap() = match _NO_SOCKS5 {
        false => {
            info!("TT {}, Server (socks5 mode)", env!("CARGO_PKG_VERSION"));
            thread::spawn( move || server_socks5::handle_connection(rx_socks5, BUFFER_SIZE));
            true
        },
        true => false
    };

    let time_now = utils::get_secs_now() / 60;
    let _tx_tun = tx_tun.clone();
    let _tx_socks5 = tx_socks5.clone();
    if (PORT_END - PORT_START) > 2 {
        thread::spawn( move || start_listener(_tx_tun, _tx_socks5, KEY, METHOD, BIND_ADDR, PORT_START, PORT_END, time_now - 1));
        thread::sleep(time::Duration::from_millis(100));
    }

    let _tx_tun = tx_tun.clone();
    let _tx_socks5 = tx_socks5.clone();
    thread::spawn( move || start_listener(_tx_tun, _tx_socks5, KEY, METHOD, BIND_ADDR, PORT_START, PORT_END, time_now));
    thread::sleep(time::Duration::from_millis(100));

    let _tx_tun = tx_tun.clone();
    let _tx_socks5 = tx_socks5.clone();
    thread::spawn( move || start_listener(_tx_tun, _tx_socks5, KEY, METHOD, BIND_ADDR, PORT_START, PORT_END, time_now + 1));

    loop {
        thread::sleep(time::Duration::from_secs(2));
        let time_now = utils::get_secs_now();
        if time_now % 60 >= 2 { continue; };  // once a minute
        thread::sleep(time::Duration::from_secs(3));    // wait for conflicted port to close itself,
                                                        // and not conflict with any thread
                                                        // that waiting for this same port
        let _tx_tun = tx_tun.clone();
        let _tx_socks5 = tx_socks5.clone();
        thread::spawn( move || start_listener(
            _tx_tun, _tx_socks5, KEY, METHOD, BIND_ADDR, PORT_START, PORT_END, utils::get_secs_now()/60 + 1)
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

fn start_listener(tx_tun: mpsc::Sender<(net::TcpStream, Encoder)>, tx_socks5: mpsc::Sender<(net::TcpStream, Encoder)>,
        KEY:&'static str, METHOD:&EncoderMethods, BIND_ADDR:&'static str,
        PORT_RANGE_START:u32, PORT_RANGE_END:u32, time_start:u64) {
    let otp = utils::get_otp(KEY, time_start);
    let port = utils::get_port(otp, PORT_RANGE_START, PORT_RANGE_END);
    let lifetime = utils::get_lifetime(otp);
    let encoder = match METHOD {
        EncoderMethods::AES256 => Encoder::AES256(AES256GCM::new(KEY, otp)),
        EncoderMethods::ChaCha20 => Encoder::ChaCha20(ChaCha20::new(KEY, otp)),
    };
    debug!("Open port : [{}], lifetime: [{}]", port, lifetime);

    let streams = Arc::new(Mutex::new(Vec::new())); 
    let flag_stop = Arc::new(Mutex::new(false));
/*
    let listener = match net::TcpListener::bind(format!("{}:{}", BIND_ADDR, port)) {
        Ok(listener) => listener,
        Err(err) => {
            error!("Error binding port: [{}], {}", port, err);
            return
        }
    };

*/
    let listener;
    let mut retry = 0;
    loop {
        match net::TcpListener::bind(format!("{}:{}", BIND_ADDR, port)) {
            Ok(_listener) => {
                listener = _listener;
                break;
            },
            Err(err) if err.kind() != std::io::ErrorKind::AddrInUse => {
                error!("Error binding port: [{}], {:?}", port, err);
                return
            },
            Err(_) => debug!("Port: [{}] in use, {:?}, retry in 2 secs...", port, thread::current().id())
        }
        retry += 1;
        thread::sleep(time::Duration::from_secs(2));
        if retry >= 33 {     // give up after 66 secs
            error!("Failed binding port: [{}], after {} secs", port, retry * 2);
            return
        }
    }

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
            thread::sleep(time::Duration::from_secs(2));
            let time_now = utils::get_secs_now();
            if time_now % 60 >= 2 || time_now/60 < time_start { continue };  // once a minute
            let time_diff = (time_now / 60 - time_start) as u8;

            // check lifetime
            if time_diff >= lifetime || time_diff > 2 && _streams.lock().unwrap().len() == 0 {
                // sleep some secs, to avoid that we always disconnect the client at the first
                // secs of every minute, that's a obvious traffic pattern as well.
                thread::sleep(time::Duration::from_secs((rand::random::<u8>() % 60) as u64));
                *_flag_stop.lock().unwrap() = true;
                drop(_streams);
                drop(_flag_stop);
                net::TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
                break;
            }
            // avoid conflicted ports, stop listening, but do not kill established connections
            else if utils::get_port(utils::get_otp(KEY, time_now/60+1), PORT_RANGE_START, PORT_RANGE_END) == port {
                // time_diff > 0
                if time_diff > 0 {
                    *_flag_stop.lock().unwrap() = true;
                    drop(_streams);
                    drop(_flag_stop);
                    net::TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
                    break;
                }
                // time_diff == 0
                else {
                    // do nothing, let the new thread wait or fail
                }
            }
        }
    });

    let mut buf_peek = [0u8; 512];
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

        let tx_tun = tx_tun.clone();
        let tx_socks5 = tx_socks5.clone();
        let streams = streams.clone();
        let _encoder = encoder.clone();
        thread::spawn( move || {
            if *SOCKS5_MODE.lock().unwrap() && *TUN_MODE.lock().unwrap() {
                let len = _stream.peek(&mut buf_peek).expect("Failed: _stream.peek()");
                let (data_len, offset) = _encoder.decode(&mut buf_peek[..len]);
                //debug!("peek length: {}, data length: {}", len, data_len);
                if (data_len == 3 || data_len == 4) && buf_peek[offset as usize - data_len] == 0x05 {
                    tx_socks5.send((_stream, _encoder)).expect("Failed: tx_socks5.send()");
                }
                else {
                    tx_tun.send((_stream, _encoder)).unwrap();
                    streams.lock().unwrap().push(stream);       // only push tun mode streams into that, to disconnect
                }
            }
            else if *SOCKS5_MODE.lock().unwrap(){
                tx_socks5.send((_stream, _encoder)).expect("Failed: tx_socks5.send()");
            }
            else if *TUN_MODE.lock().unwrap(){
                tx_tun.send((_stream, _encoder)).unwrap();
                streams.lock().unwrap().push(stream);       // push wild streams here, waiting to die
            }
        });
    }
    debug!("Close port: [{}], lifetime: [{}]", port, lifetime);
    
    // If we kill all the existing streams, then the client has to establish a new one to
    // resume downloading process. Also, if we kill streams at the very first seconeds of each
    // minute, this seems to be a traffic pattern.
    // so we disable it for socks5 mode, as client_frontend_socks5 will just drop the connection.
    
    if !*NO_PORT_JUMP.lock().unwrap(){
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
