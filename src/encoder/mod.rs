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

pub trait EncoderBasicTrait {
    fn encode(&self, data: &mut [u8], size: usize) -> usize;
    fn decode(&self, data: &mut [u8]) -> (usize, i32);
}
