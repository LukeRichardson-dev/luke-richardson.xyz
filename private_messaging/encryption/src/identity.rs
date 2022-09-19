use std::{collections::HashMap, hash::Hash};
use openssl::{bn::BigNum, hash::MessageDigest};
use openssl::dh::Dh;
use openssl::pkey::{Private, PKey};
use openssl::sign::Signer;
use openssl::envelope::Seal;
use crate::shared::{Shared, SharedBuilder};

pub struct Identity<T: Eq + Hash> {
    pub key: Dh<Private>,
    shared_secrets: HashMap<T, Shared>,
}

impl<T: Eq + Hash> Identity<T> {
    pub fn new(key: Dh<Private>, shared_secrets: Option<HashMap<T, Shared>>) -> Self {
        Self {
            key,
            shared_secrets: shared_secrets.unwrap_or(HashMap::default()),
        }
    }

    pub fn create() -> Self {
        let key = Dh::get_2048_256().unwrap()
            .generate_key().unwrap();

        Self { key, shared_secrets: HashMap::new() }
    }

    pub fn add_secret(&mut self, id: T, public_key: BigNum) -> &Shared {
        self.shared_secrets
            .entry(id)
            .or_insert_with(
                || SharedBuilder::new(public_key)
                    .generate_secret(self.key.private_key())
                    .unwrap().build()
            )
    }

    pub fn get_secret(&self, id: &T) -> Result<&Shared, ()> {
        self.shared_secrets.get(id).ok_or(())
    }

    pub fn sign(&self, payload: &Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let dh_copy = PKey::from_dh(
                Dh::from_pqg(
                    self.key.prime_p().to_owned()?,
                    Some(self.key.prime_q().unwrap().to_owned()?),
                    self.key.generator().to_owned()?,
                )?.generate_key()?
            );

        let mut signer = Signer::new(
            MessageDigest::sha256(), 
            &dh_copy.as_ref().unwrap(),
        )?;
        signer.update(payload)?;

        let mut buf = vec![0u8; signer.len()?];
        signer.sign(&mut buf)?;

        Ok(buf)
    }
}
