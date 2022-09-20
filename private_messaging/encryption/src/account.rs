use openssl::{
    pkey::{PKey, Public, Private}, 
    bn::BigNum, 
    sign::Signer, 
    hash::MessageDigest,

};

pub type ID = String;


#[derive(Debug, Clone)]
pub struct AmbiguousAccount {

    pub id: ID,
    pub public_key: PKey<Public>,

    pub info: Vec<u8>,

}

#[derive(Debug, Clone)]
pub struct ImplicitAccount {

    pub id: ID,
    pub public_key: PKey<Public>,
    pub private_key: PKey<Private>,

    pub info: Vec<u8>,

}

impl ImplicitAccount {
    
    pub fn sign(&self, data: Vec<u8>) -> Vec<u8> {

        let digest = MessageDigest::sha3_256();
        let mut signer = Signer::new(digest, &self.private_key).unwrap();

        signer.update(&data).unwrap();
        signer.sign_to_vec().unwrap()

    }

}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct AccountConnection {

    imp_id: ID,
    amb_id: ID,

    pub secret: Vec<u8>,

}

impl AccountConnection {

    pub fn from_accounts(
        implicit: &ImplicitAccount, 
        ambiguous: &AmbiguousAccount,
    ) -> Self {
        // let dh = implicit.private_key.dh().unwrap();

        Self {
            imp_id: implicit.id.clone(),
            amb_id: ambiguous.id.clone(),
            secret: Vec::new(),
            // dh.compute_key(
            //     BigNum::from_slice(
            //         &ambiguous.public_key.raw_public_key().unwrap()
            //     ).unwrap().as_ref()
            // ).unwrap(),
        }
    }

}