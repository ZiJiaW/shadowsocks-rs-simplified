use openssl::symm::{encrypt, Cipher, decrypt};

pub struct Encypter {
    cipher: Cipher,
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl Encypter {
    pub fn new() -> Encypter
    {
        let cipher = Cipher::aes_128_cbc();
        let key = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F".to_vec();
        let iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07".to_vec();
        Encypter {cipher, key, iv}
    }

    pub fn encode(&mut self, text: &[u8]) -> Vec<u8>
    {
        encrypt(self.cipher, &self.key, Some(&self.iv), text).unwrap()
    }

    pub fn decode(&mut self, text: &[u8]) -> Vec<u8>
    {
        decrypt(self.cipher, &self.key, Some(&self.iv), text).unwrap()
    }
}