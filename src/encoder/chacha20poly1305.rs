#![allow(non_snake_case)]
#![allow(dead_code)]
extern crate rand;
extern crate crypto;

use crypto::aead::*;
use crypto::chacha20poly1305::ChaCha20Poly1305;

use crate::utils;

#[derive(Debug,Clone)]
pub struct Encoder {
    key_bytes: [u8;32],
    size_xor_bytes: [u8;32],
}

impl Encoder {
    pub fn new(KEY:&'static str, otp:u32) -> Encoder {
        Encoder {
            key_bytes:utils::get_key_bytes(KEY, otp),
            size_xor_bytes: utils::get_size_xor_bytes(KEY, otp),
        }
    }

    pub fn encode_data_size(&self, size: usize, random_bytes:&[u8]) -> [u8;2] {
        //assert!(size<=65536);
        [ 
            (size >> 8) as u8 ^ self.size_xor_bytes[(random_bytes[0] % 32) as usize], 
            (size & 0xff) as u8 ^ self.size_xor_bytes[(random_bytes[1] % 32) as usize]
        ]
    }

    pub fn decode_data_size(&self, bytes: &[u8], random_bytes: &[u8]) -> usize {
        (
            (((bytes[0] as u16) ^ (self.size_xor_bytes[(random_bytes[0] % 32) as usize]) as u16) << 8) 
            +
            (bytes[1] ^ self.size_xor_bytes[(random_bytes[1] % 32) as usize]) as u16
        ) as usize
    }
    pub fn encode_random_size(&self, random_bytes:&[u8]) -> u8 {
        (random_bytes.len() as u8) ^ (self.size_xor_bytes[(random_bytes[0] % 32) as usize ])
    }

    pub fn decode_random_size(&self, random_size:u8, random_bytes_0:u8) -> usize {
        (random_size ^ (self.size_xor_bytes[(random_bytes_0 % 32) as usize])) as usize
    }

    pub fn encode(&self, input: &[u8], output: &mut [u8]) -> usize {
        let random_bytes = utils::get_random_bytes();
        //let nounce = &utils::md5_bytes_from_bytes(&random_bytes)[ .. 8];
        let nounce = &random_bytes[ .. 8];
        let aad = &self.key_bytes[ .. 8];
        let mut tag = vec![0u8;16];
        let data_start = 1 + random_bytes.len() + 2;
        let data_len = input.len();

        let mut cipher = ChaCha20Poly1305::new(&self.key_bytes, nounce, aad);
        cipher.encrypt(&input, &mut output[data_start..data_start+data_len], &mut tag);

        output[0] = self.encode_random_size(&random_bytes);
        output[1 .. random_bytes.len() + 1].copy_from_slice(&random_bytes);
        output[data_start-2 .. data_start].copy_from_slice(&self.encode_data_size(data_len, &random_bytes[..2]));
        output[data_start+data_len .. data_start+data_len+16 ].copy_from_slice(&tag);
        data_start + data_len + 16
    }

    pub fn decode(&self, input: &[u8], output: &mut [u8]) -> (usize, usize) {
        let input_len = input.len();
        let random_size = self.decode_random_size(input[0], input[1]);
        if input_len <= 1 + random_size + 2 + 16 {
            return (0, 0)
        }

        let random_bytes = &input[1 .. random_size + 1];
        let data_start = 1 + random_size + 2;
        let data_len = self.decode_data_size(&input[data_start-2..data_start], &random_bytes[..2]);
        if input_len < 1 + random_size + 2 + data_len + 16 {
            return (0, 0)
        }

        //let nounce = &utils::md5_bytes_from_bytes(random_bytes)[ .. 8];
        let nounce = &random_bytes[..8];
        let data = &input[data_start .. data_start + data_len];
        let tag = &input[data_start + data_len .. data_start + data_len + 16];
        let aad = &self.key_bytes[ .. 8];
    
        let mut cipher = ChaCha20Poly1305::new(&self.key_bytes, nounce, aad);
        if cipher.decrypt(&data, &mut output[..data_len], &tag) {
            (data_len, data_start + data_len + 16)
        }
        else{
            (0, 0)
        }
    }
}


pub fn test_encoder() {
    let input = [1,2,3,4,19,94];
    let enc = Encoder::new("password12", 11);

    let mut output = vec![0u8;1024];
    let mut output2 = vec![0u8;1024];
    let size = enc.encode(&input, &mut output);
    println!("encode2 size:{}\nresult: {:?}", size, &output[..size]);
    let (size, offset) = enc.decode(&output[..size], &mut output2);
    println!("decode2 size:{}\noffset:{}\nresult: {:?}", size, offset, &output2[..size])
}

