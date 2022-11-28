use encryption::account::{ImplicitAccount, AmbiguousAccount, ID};
use openssl::symm::{Cipher, decrypt, encrypt};
use openssl::{sign::Verifier, hash::MessageDigest};
use openssl::pkey::{PKey, Public};
use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey, Algorithm, agree_ephemeral};

static IV: &[u8; 16] = b"efwoifhiolwehfim";

#[derive(Debug, Clone)]
pub struct OutgoingMessage {

    pub user: ImplicitAccount,
    pub contents: Vec<u8>,
    pub to: AmbiguousAccount,

}

impl OutgoingMessage {
    
    pub fn to_payload(&self, key: &Vec<u8>) -> MessagePayload {

        let cipher = Cipher::aes_256_cbc();
        let encrypted = encrypt(cipher, key, Some(IV), &self.contents).unwrap();

        MessagePayload { 
            id: self.user.id.clone(),
            key: self.user.private_key.,
            contents: encrypted,
            signature: self.user.sign(self.contents.clone()),
        }

    }
}

#[derive(Debug, Clone)]
pub struct IncomingMessage {

    account: AmbiguousAccount,
    contents: Vec<u8>,
    signature: Vec<u8>,

}

impl IncomingMessage {

    pub fn new(
        account: AmbiguousAccount,
        contents: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        Self { account, contents, signature }
    }
    
    pub fn verify(&self) -> bool {

        let mut verifier = Verifier::new(
            MessageDigest::sha3_256(), 
            &self.account.public_key,
        ).unwrap();

        verifier.update(&self.contents).unwrap();
        verifier.verify(&self.signature).unwrap()

    }

    pub fn from_payload(payload: MessagePayload) -> Self {
        Self {
            account: AmbiguousAccount { 
                public_key: payload.key.clone(), 
                id: payload.id,
                info: vec![],
            },
            contents: payload.contents,
            signature: payload.signature,
        }
    }

}

#[derive(Debug, Clone)]
pub struct MessagePayload {

    pub id: ID,
    pub key: PKey<Public>,
    pub contents: Vec<u8>,
    pub signature: Vec<u8>,

}

