use serde::{Serialize, Deserialize};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use std::hash::Hash;


pub struct ForeignKeychain {
    pub public_key: PublicKey,
    pub shared_key: SharedSecret,
}

impl ForeignKeychain {
    pub fn new(public_key: PublicKey, static_secret: StaticSecret) -> Self {
        Self {
            public_key: public_key,
            shared_key: static_secret.diffie_hellman(&public_key),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum SealedMessage<'a> {
    Nil,
    Sync {
        userid: &'a str,
        password: &'a str,
        public_key: &'a[u8],
    },
    Communicate {
        userid: &'a str,
        signature: &'a[u8],
        message: &'a[u8],
    },
    RedBox {
        userid: &'a str,
        message: &'a[u8],
    },
}

pub enum EncryptionData<'a> {
    Passed {
        encrypted: bool,
        username: &'a str,
        sharedkey: &'a SharedSecret,
    },
    Failed {
        target: &'a str,
        encrypted: bool,
    },
}

pub struct DecodedMessage<'a> {
    pub encryption_data: EncryptionData<'a>,
    pub message: &'a [u8],
}


pub trait KeyStore {

    type ID: Hash;

    fn set_key(&mut self, id: Self::ID, keychain: ForeignKeychain) -> Result<Option<ForeignKeychain>, ()>;
    fn get_key(&mut self, id: Self::ID) -> Option<&ForeignKeychain>;

}