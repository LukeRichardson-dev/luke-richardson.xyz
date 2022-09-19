use crate::account::{ID};
use encryption::account::{ImplicitAccount, AmbiguousAccount};
use openssl::{sign::Verifier, hash::MessageDigest};
use openssl::pkey::{PKey, Public};

pub struct OutgoingMessage {

    pub user: ImplicitAccount,
    pub contents: Vec<u8>,
    pub to: AmbiguousAccount,

}

impl OutgoingMessage {
    
    pub fn to_payload(&self) -> MessagePayload {

        MessagePayload { 
            id: self.user.id.clone(),
            key: self.user.public_key.clone(), 
            contents: self.contents.clone(), 
            signature: self.user.sign(self.contents.clone()),
        }

    }
}

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

