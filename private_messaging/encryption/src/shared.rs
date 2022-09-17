use std::convert::TryInto;

use openssl::{bn::{BigNum, BigNumRef}, dh::Dh, aes::{AesKey, aes_ige, wrap_key}, rand::rand_bytes, symm::Mode};
pub struct Shared {

    pub_key: BigNum,
    iv: [u8; 256],
    pub shared_secret: Vec<u8>,

}

impl Shared {

    pub fn new(pub_key: BigNum, shared_secret: Vec<u8>) -> Self {

        let mut iv = [0u8; 256];
        rand_bytes(&mut iv).unwrap();

        Self { pub_key, shared_secret, iv }

    }

    pub fn encrypt(&mut self, payload: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>>{

        let (_in, mut out, key) = self.generate_encryption_data(payload);
        
        let key = AesKey::new_encrypt(&key).map_err(|err| {
            println!("{:?}", err);
        }).unwrap();

        aes_ige(&_in, &mut out, &key, &mut self.iv, Mode::Encrypt);

        Ok(out)

    }

    pub fn decrypt(&mut self, payload: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>>{

        let (_in, mut out, key) = self.generate_encryption_data(payload);

        let key = AesKey::new_decrypt(&key).unwrap();

        aes_ige(&_in, &mut out, &key, &mut self.iv, Mode::Decrypt);

        Ok(out)

    }

    fn generate_encryption_data(&self, payload: Vec<u8>) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        let length = (16 - (payload.len() % 16)) % 16;
        println!("{}-{}", payload.len(), length);

        let mut _in = payload.clone();
        _in.append(&mut vec![0; length]);

        let out = vec![0; payload.len() + length];

        println!("{}", self.shared_secret[0..32].len());
        
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

        Self { pub_key, _shared_secret: None }

    }

    pub fn generate_secret(&self, priv_key: &BigNumRef) -> Result<Self, Box<dyn std::error::Error>> {
        let dh = Dh::get_2048_256()?
            .set_private_key(priv_key.to_owned()?)?;

        Ok(Self {
            _shared_secret: Some(dh.compute_key(&self.pub_key)?),
            pub_key: self.pub_key.to_owned()?,
        })

    }

    pub fn build(&self) -> Shared {

        Shared::new(
            self.pub_key.to_owned().unwrap(), 
            self._shared_secret.as_ref().unwrap().to_vec(),
        )

    }

}