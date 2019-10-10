pub mod aes256gcm;
pub mod chacha20poly1305;

pub enum EncoderMethods {
    AES256,
    ChaCha20
}

#[derive(Debug,Clone)]
pub enum Encoder {
    AES256 (aes256gcm::AES256GCM),
    ChaCha20  (chacha20poly1305::ChaCha20),
}

impl Encoder{

    pub fn encode(&self, input: &[u8], output: &mut [u8]) -> usize {
        match self {
            Encoder::AES256(obj) => obj.encode(input, output),
            Encoder::ChaCha20(obj) => obj.encode(input, output),
        }
    }
    pub fn decode(&self, input: &[u8], output: &mut [u8]) -> (usize, i32) {
        match self {
            Encoder::AES256(obj) => obj.decode(input, output),
            Encoder::ChaCha20(obj) => obj.decode(input, output),
        }
    }

}

pub trait EncoderEntityTrait {
    fn encode_data_size(&self, size: usize, random_bytes:&[u8]) -> [u8;2];

    fn decode_data_size(&self, bytes: &[u8], random_bytes: &[u8]) -> usize;

    fn encode_random_size(&self, random_bytes:&[u8]) -> u8;

    fn decode_random_size(&self, random_size:u8, random_bytes_0:u8) -> usize;

    fn encode(&self, input: &[u8], output: &mut [u8]) -> usize;

    fn decode(&self, input: &[u8], output: &mut [u8]) -> (usize, i32);
}
