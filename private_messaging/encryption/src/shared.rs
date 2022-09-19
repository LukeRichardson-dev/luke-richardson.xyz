use std::convert::TryInto;

use openssl::{
    bn::{BigNum, BigNumRef},
    dh::Dh,
    rand::rand_bytes,
    symm::{Cipher, decrypt, encrypt},
};

pub static NO_SECRET_KEY: &'static str = "Secret key has not yet been generated";

pub struct Shared {
    pub_key: BigNum,
    iv: [u8; 16],
    pub shared_secret: Vec<u8>,
}

impl Shared {
    pub fn new(pub_key: BigNum, shared_secret: Vec<u8>) -> Self {
        let mut iv = [0u8; 16];
        rand_bytes(&mut iv).unwrap();

        Self {
            pub_key,
            shared_secret,
            iv,
        }
    }

    pub fn encrypt(&mut self, payload: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let (_in, _, key) = self.generate_encryption_data(payload);
        
        Ok(encrypt(Cipher::aes_256_cbc(), &key, Some(&self.iv), &_in)?)
    }

    pub fn decrypt(&mut self, payload: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let (_in, _, key) = self.generate_encryption_data(payload);
        
        Ok(decrypt(Cipher::aes_256_cbc(), &key, Some(&self.iv), &_in)?)
    }

    fn generate_encryption_data(&self, payload: Vec<u8>) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        let length = (16 - (payload.len() % 16)) % 16;

        let mut _in = payload.clone();
        _in.append(&mut vec![0; length]);

        let out = vec![0; payload.len() + length];

        let key: [u8; 32] = self.shared_secret[0..32].try_into().unwrap();

        (_in, out, key)
    }
}

#[derive(Debug)]
pub struct SharedBuilder {
    pub_key: BigNum,
    _shared_secret: Option<Vec<u8>>,
}


impl SharedBuilder {
    pub fn new(pub_key: BigNum) -> Self {
        Self {
            pub_key,
            _shared_secret: None,
        }
    }

    pub fn generate_secret(
        &self,
        priv_key: &BigNumRef,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let dh = Dh::get_2048_256()?.set_private_key(priv_key.to_owned()?)?;

        Ok(Self {
            _shared_secret: Some(dh.compute_key(&self.pub_key)?),
            pub_key: self.pub_key.to_owned()?,
        })
    }

    pub fn build(&self) -> Shared {
        Shared::new(
            self.pub_key.to_owned().unwrap(),
            self._shared_secret.as_ref().expect(NO_SECRET_KEY).to_vec(),
        )
    }
}
