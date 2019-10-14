#![allow(non_snake_case)]
extern crate oath;
extern crate rand;
extern crate sha2;

use rand::Rng;
use std::time;
use sha2::{Sha256, Digest};

pub fn get_secs_now() -> u64 {
    let sys_time = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap();
    sys_time.as_secs()
}

pub fn sha256_bytes(data:&str) -> [u8;32] {
    let mut buf  = [0u8;32];
    let mut hasher = Sha256::new();
    hasher.input(data.as_bytes());
    buf.copy_from_slice(hasher.result().as_slice());
    buf
}

pub fn get_key_bytes(key:&str, otp:u32) -> [u8;32] {
    let mut key = key.to_string();
    key.push_str(&format!("ThE=TuNnEL+SaLt-[];',/{}", otp));
    sha256_bytes(&key)
}

pub fn get_size_xor_bytes(key:&str, otp:u32) -> [u8;32] {
    let mut key = key.to_string();
    key.push_str(&format!("SaLT.fOr/SiZe+=Xor-{}", otp));
    sha256_bytes(&key)
}

pub fn get_random_bytes() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut length = rng.gen_range(12, 33);
    let mut result = Vec::with_capacity(length);
    while length > 0  {
        result.push(rng.gen::<u8>());
        length -= 1;
    };
    result
}

pub fn get_otp(KEY:&str, time_minutes:u64) -> u32 {
    oath::hotp_raw(&sha256_bytes(KEY),  time_minutes, 6) as u32
}

pub fn get_port(otp:u32, PORT_RANGE_START:u32, PORT_RANGE_END:u32) -> u32 {
    if PORT_RANGE_START == PORT_RANGE_END {
        PORT_RANGE_START
    }
    else {
        otp % (PORT_RANGE_END - PORT_RANGE_START) + PORT_RANGE_START
    }
}

pub fn get_time_span(otp:u32) -> u8 {
    (otp % 15 + 1) as u8
}
