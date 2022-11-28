use rand_core::OsRng;
use security::{DecodedMessage, EncryptionData, KeyStore, SealedMessage};
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use std::io::Error;
use tokio::sync::{mpsc, watch};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

mod security;
mod user;
pub mod secure;

use security::ForeignKeychain;

struct SocketGuard<'a, KS: KeyStore<ID = &'a str>> {
    guard_key: StaticSecret,
    keys: KS,
    in_rx: mpsc::Receiver<SealedMessage<'a>>,
    out_tx: watch::Sender<Option<SealedMessage<'a>>>,
    out_rx: watch::Receiver<Option<SealedMessage<'a>>>,
}

impl<'a, KS: KeyStore<ID = &'a str>> SocketGuard<'a, KS> {
    pub fn new(in_rx: mpsc::Receiver<SealedMessage<'a>>, keystore: KS) -> Self {
        let (out_tx, out_rx) = watch::channel(None);
        Self {
            guard_key: StaticSecret::new(OsRng),
            in_rx: in_rx,
            keys: keystore,
            out_rx,
            out_tx,
        }
    }

    pub async fn next(&mut self) -> Option<DecodedMessage> {
        if let Some(msg) = self.in_rx.recv().await {
            return match msg {
                SealedMessage::Nil => None,
                SealedMessage::Sync {
                    userid,
                    password,
                    public_key,
                } => {
                    self.sync(
                        userid,
                        password,
                        PublicKey::from(public_key.iter().enumerate().fold(
                            [0u8; 32],
                            |mut acc, (idx, &v)| {
                                acc[idx] = v;
                                acc
                            },
                        )),
                    );
                    None
                }
                SealedMessage::Communicate {
                    userid,
                    message,
                    signature,
                } => Some(self.communicate(userid, message, signature)),
                SealedMessage::RedBox { userid, message } => Some(self.red_box(userid, message)),
            };
        }

        None
    }

    fn sync(&mut self, userid: &'a str, _password: &'a str, public_key: PublicKey) {
        let ss = self.guard_key.diffie_hellman(&public_key);
        self.keys
            .set_key(
                userid,
                ForeignKeychain {
                    public_key,
                    shared_key: ss,
                },
            )
            .unwrap();
    }

    fn communicate(
        &mut self,
        userid: &'a str,
        message: &'a [u8],
        signature: &'a [u8],
    ) -> DecodedMessage {
        let key = self.keys.get_key(userid).unwrap(); // TODO: Remove this
        DecodedMessage {
            encryption_data: EncryptionData::Passed {
                encrypted: false,
                username: userid,
                sharedkey: &key.shared_key,
            },
            message: message,
        }
    }

    fn red_box(&mut self, userid: &'a str, message: &'a [u8]) -> DecodedMessage {
        todo!()
    }
}

#[tokio::main]
async fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::{
        DecodedMessage, EncryptionData, ForeignKeychain, KeyStore, SealedMessage, SocketGuard,
    };

    #[derive(Default)]
    struct TestKs<'a> {
        keys: HashMap<&'a str, ForeignKeychain>,
    }

    impl<'a> KeyStore for TestKs<'a> {
        type ID = &'a str;

        fn set_key(
            &mut self,
            id: Self::ID,
            keychain: ForeignKeychain,
        ) -> Result<Option<ForeignKeychain>, ()> {
            let kc = self.keys.insert(id, keychain);
            Ok(kc)
        }

        fn get_key(&mut self, id: Self::ID) -> Option<&ForeignKeychain> {
            self.keys.get(id)
        }
    }

    const EXAMPLE_PUBLIC_KEY_BYTES: &'static [u8; 32] = &[0u8; 32];
    const EXAMPLE_STATIC_KEY_BYTES: &'static [u8; 32] = &[1u8; 32];
    const TEST_USERNAME: &'static str = "TEST_USERNAME";
    const TEST_PASSWORD: &'static str = "TEST_PASSWORD";
    const TEST_MESSAGE: &'static [u8] = b"Hello World";

    #[test]
    fn example_keystore() {
        let mut ks = TestKs::default();

        ks.set_key(
            TEST_USERNAME,
            ForeignKeychain::new(
                PublicKey::from(*EXAMPLE_PUBLIC_KEY_BYTES),
                StaticSecret::from(*EXAMPLE_STATIC_KEY_BYTES),
            ),
        )
        .unwrap();

        assert_eq!(
            ks.get_key(TEST_USERNAME).unwrap().public_key.as_bytes(),
            EXAMPLE_PUBLIC_KEY_BYTES
        );

        let old = ks
            .set_key(
                TEST_USERNAME,
                ForeignKeychain::new(
                    PublicKey::from(*EXAMPLE_STATIC_KEY_BYTES),
                    StaticSecret::from(*EXAMPLE_STATIC_KEY_BYTES),
                ),
            )
            .unwrap();

        assert_eq!(old.unwrap().public_key.as_bytes(), EXAMPLE_PUBLIC_KEY_BYTES);
        assert_eq!(
            ks.get_key(TEST_USERNAME).unwrap().public_key.as_bytes(),
            EXAMPLE_STATIC_KEY_BYTES
        );
    }

    #[tokio::test]
    async fn socket_guard_sync() {
        use tokio::sync::mpsc;
        let (tx, mut rx) = mpsc::channel(1);

        let mut guard = SocketGuard::new(rx, TestKs::default());
        tokio::spawn(async move {
            guard.next().await;
        });

        tx.send(SealedMessage::Sync {
            userid: TEST_USERNAME,
            password: TEST_PASSWORD,
            public_key: EXAMPLE_PUBLIC_KEY_BYTES,
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn socket_guard_communicate() {
        use tokio::sync::mpsc;
        let (tx, rx) = mpsc::channel(1);

        tx.send(SealedMessage::Sync {
            userid: TEST_USERNAME,
            password: TEST_PASSWORD,
            public_key: EXAMPLE_PUBLIC_KEY_BYTES,
        })
        .await
        .unwrap();
        let mut guard = SocketGuard::new(rx, TestKs::default());

        assert!(guard.next().await.is_none());

        tx.send(SealedMessage::Communicate {
            userid: TEST_USERNAME,
            signature: &[0u8; 32],
            message: TEST_MESSAGE,
        })
        .await
        .unwrap();

        let nxt: DecodedMessage = guard.next().await.unwrap();

        assert!(match nxt.encryption_data {
            EncryptionData::Passed {
                encrypted: _,
                username: _,
                sharedkey: _,
            } => true,
            _ => false,
        });

        println!("{:?}", nxt.message);
    }
}
