#![allow(non_snake_case)]
extern crate rand;
extern crate crypto;

use crypto::aead::*;
use crypto::aes::KeySize;
use crypto::aes_gcm::AesGcm;

use crate::utils;
use crate::encoder::EncoderEntityTrait;

#[derive(Debug,Clone)]
pub struct AES256GCM {
    key_bytes: [u8;32],
    size_xor_bytes: [u8;32],
}

impl AES256GCM {
    pub fn new(KEY:&'static str, otp:u32) -> AES256GCM {
        AES256GCM {
            key_bytes:utils::get_key_bytes(KEY, otp),
            size_xor_bytes: utils::get_size_xor_bytes(KEY, otp),
        }
    }
}

impl EncoderEntityTrait for AES256GCM {
    fn encode_data_size(&self, size: usize, random_bytes:&[u8]) -> [u8;2] {
        //assert!(size<=65536);
        [ 
            (size >> 8) as u8 ^ self.size_xor_bytes[(random_bytes[0] % 32) as usize], 
            (size & 0xff) as u8 ^ self.size_xor_bytes[(random_bytes[1] % 32) as usize]
        ]
    }

    fn decode_data_size(&self, bytes: &[u8], random_bytes: &[u8]) -> usize {
        (
            (((bytes[0] as u16) ^ (self.size_xor_bytes[(random_bytes[0] % 32) as usize]) as u16) << 8) 
            +
            (bytes[1] ^ self.size_xor_bytes[(random_bytes[1] % 32) as usize]) as u16
        ) as usize
    }
    fn encode_random_size(&self, random_bytes:&[u8]) -> u8 {
        (random_bytes.len() as u8) ^ (self.size_xor_bytes[(random_bytes[0] % 32) as usize ])
    }

    fn decode_random_size(&self, random_size:u8, random_bytes_0:u8) -> usize {
        (random_size ^ (self.size_xor_bytes[(random_bytes_0 % 32) as usize])) as usize
    }

    fn encode(&self, input: &[u8], output: &mut [u8]) -> usize {
        let random_bytes = utils::get_random_bytes();
        let mut nounce = vec![0u8; 8];
        nounce.copy_from_slice(&random_bytes[ .. 8]);
        nounce.append(&mut vec![0,0,0,0]);

        let aad = &self.key_bytes[ .. 8];
        let mut tag = vec![0u8;16];
        let data_start = 1 + random_bytes.len() + 2;
        let data_len = input.len();

        let mut cipher = AesGcm::new(KeySize::KeySize256, &self.key_bytes, &nounce, aad);
        cipher.encrypt(&input, &mut output[data_start..data_start+data_len], &mut tag);

        output[0] = self.encode_random_size(&random_bytes);
        output[1 .. random_bytes.len() + 1].copy_from_slice(&random_bytes);
        output[data_start-2 .. data_start].copy_from_slice(&self.encode_data_size(data_len, &random_bytes[..2]));
        output[data_start+data_len .. data_start+data_len+16 ].copy_from_slice(&tag);
        data_start + data_len + 16
    }

    fn decode(&self, input: &[u8], output: &mut [u8]) -> (usize, i32) {
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
        let mut nounce = vec![0u8; 8];
        nounce.copy_from_slice(&random_bytes[ .. 8]);
        nounce.append(&mut vec![0,0,0,0]);
        let data = &input[data_start .. data_start + data_len];
        let tag = &input[data_start + data_len .. data_start + data_len + 16];
        let aad = &self.key_bytes[ .. 8];
    
        let mut cipher = AesGcm::new(KeySize::KeySize256, &self.key_bytes, &nounce, aad);
        if cipher.decrypt(&data, &mut output[..data_len], &tag) {
            (data_len, (data_start + data_len + 16) as i32)
        }
        else{
            (0, -1)
        }
    }
}
