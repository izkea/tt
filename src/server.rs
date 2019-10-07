#![allow(non_snake_case)]
extern crate job_scheduler;

use std::net;
use std::time;
use std::thread;
use std::sync::{Arc, Mutex};
use job_scheduler::{JobScheduler, Job};

use crate::utils;
use crate::server_backend_socks5;
use crate::encoder::chacha20poly1305::Encoder;

pub fn run(KEY:&'static str, BIND_ADDR:&'static str, PORT_RANGE_START:u32, PORT_RANGE_END:u32, MTU:usize) {
    let time_now = utils::get_secs_now() / 60;
    thread::spawn( move || server_backend_socks5::run_merino());
    thread::spawn( move || start_listener(KEY, BIND_ADDR, PORT_RANGE_START, PORT_RANGE_END, MTU, time_now - 1));
    thread::spawn( move || start_listener(KEY, BIND_ADDR, PORT_RANGE_START, PORT_RANGE_END, MTU, time_now    ));
    thread::spawn( move || start_listener(KEY, BIND_ADDR, PORT_RANGE_START, PORT_RANGE_END, MTU, time_now + 1));

    // 定时任务， 每分钟启动一个新的 start_listener()
    let mut sched = JobScheduler::new();
    sched.add(Job::new("0 * * * * *".parse().unwrap(), || {
        thread::spawn( move || start_listener(
                KEY, BIND_ADDR, PORT_RANGE_START, PORT_RANGE_END, MTU, utils::get_secs_now()/60 + 1));
    }));
    loop {
        sched.tick();
        std::thread::sleep(time::Duration::from_millis(500));
    }
}

fn start_listener(KEY:&'static str, BIND_ADDR:&'static str, PORT_RANGE_START:u32, PORT_RANGE_END:u32, MTU:usize, time_start:u64) {
    let otp = utils::get_otp(KEY, time_start);
    let port = utils::get_port(otp, PORT_RANGE_START, PORT_RANGE_END);
    let time_span = utils::get_time_span(otp);
    let encoder = Encoder::new(KEY, otp);
    println!("Open port : [{}], time_span:[{}]", port, time_span);

    let streams = Arc::new(Mutex::new(Vec::new())); 
    let flag_stop = Arc::new(Mutex::new(false));
    let listener = net::TcpListener::bind(format!("{}:{}", BIND_ADDR, port)).unwrap();

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
            if time_now % 60 >= 58 || time_now/60 < time_start { continue; };  // once a minute
            let time_diff = (time_now / 60 - time_start) as u8;
            if time_diff >= time_span || time_diff > 2 && _streams.lock().unwrap().len() == 0 {
                *_flag_stop.lock().unwrap() = true;
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
        let stream = stream.unwrap();
        let _stream = stream.try_clone().unwrap();
        let encoder = encoder.clone();
        thread::spawn(move||server_backend_socks5::handle_connection(_stream, encoder, MTU));
        streams.lock().unwrap().push(stream);
    }
    println!("Close port:{}, time_span:{}", port, time_span);
    
    // #TODO If we shutdown all the existing streams, then the client has to establish a new one.
    // for now, the client_frontend_socks5 will only drop the client side streams as well.
    let lock = Arc::try_unwrap(streams).expect("Error: lock still has multiple owners");
    let streams = lock.into_inner().expect("Error: mutex cannot be locked");
    for stream in streams {
        stream.shutdown(net::Shutdown::Both).unwrap_or_else(|_err|eprintln!("Error: failed to kill streams, {}", _err));
    }
}