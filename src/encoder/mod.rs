pub mod aes256gcm;
pub mod chacha20poly1305;

pub enum EncoderMethods {
    AES256,
    ChaCha20
}

#[derive(Clone)]
pub enum Encoder {
    AES256 (aes256gcm::AES256GCM),
    ChaCha20  (chacha20poly1305::ChaCha20),
}

impl Encoder{

    pub fn encode(&self, data: &mut [u8], size: usize) -> usize {
        match self {
            Encoder::AES256(obj) => obj.encode(data, size),
            Encoder::ChaCha20(obj) => obj.encode(data, size),
        }
    }
    pub fn decode(&self, data: &mut [u8]) -> (usize, i32) {
        match self {
            Encoder::AES256(obj) => obj.decode(data),
            Encoder::ChaCha20(obj) => obj.decode(data),
        }
    }

}

pub trait EncoderEntityTrait {
    fn encode_data_size(&self, size: usize, random_bytes:&[u8]) -> [u8;2];

    fn decode_data_size(&self, bytes: &[u8], random_bytes: &[u8]) -> usize;

    fn encode_random_size(&self, random_bytes:&[u8]) -> u8;

    fn decode_random_size(&self, random_size:u8, random_bytes_0:u8) -> usize;

    fn encode(&self, data: &mut [u8], size: usize) -> usize;

    fn decode(&self, data: &mut [u8]) -> (usize, i32);
}
