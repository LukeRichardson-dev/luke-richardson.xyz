use openssl::{
    pkey::{PKey, Public, Private}, 
    bn::{BigNum, BigNumContext}, 
    sign::Signer, 
    hash::MessageDigest, 
    dh::{Dh, DhRef},
    envelope::Seal,
    derive::Deriver, pkey_ctx::{PkeyCtx, HkdfMode},
    
};
use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey, ECDH_P256, agree_ephemeral, PublicKey, self};
use ring::hmac::sign;

pub type ID = String;


#[derive(Debug, Clone)]
pub struct AmbiguousAccount<'a> {

    pub id: ID,
    pub public_key: UnparsedPublicKey<&'a [u8; 256]>,

    pub info: Vec<u8>,

}

pub struct ImplicitAccount {

    pub id: ID,
    // pub public_key: PKey<Public>,
    pub private_key: EphemeralPrivateKey,

    pub info: Vec<u8>,

}

impl ImplicitAccount {
    
    pub fn sign(&self, data: Vec<u8>) -> Vec<u8> {
        let key = PKey::from_dh(
                Dh::from_pqg(self.private_key.prime_p())
            ).unwrap();

        let digest = MessageDigest::sha3_256();
        let mut signer = Signer::new(
            digest, 
            key.as_ref(),
        ).unwrap();

        signer.update(&data).unwrap();
        signer.sign_to_vec().unwrap()

        sign(self.private_key,&data).;

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

        let key = agree_ephemeral(
            implicit.private_key, 
            &ambiguous.public_key,
            ring::error::Unspecified,
            |_| Ok(()),
        ).unwrap();

        Self {
            imp_id: implicit.id.clone(),
            amb_id: ambiguous.id.clone(),
            secret: implicit.private_key
                .compute_key(
                    ambiguous.public_key.dh().unwrap().public_key(),
                ).unwrap(),
            // dh.compute_key(
            //     &BigNum::from_slice(
            //         &pub_key.into()
            //     ).unwrap().to_owned().unwrap()
            // ).unwrap()
                // key,
                // Vec::new(),
            // dh.compute_key(
            //     BigNum::from_slice(
            //         &ambiguous.public_key.raw_public_key().unwrap()
            //     ).unwrap().as_ref()
            // ).unwrap(),
        }
    }

}