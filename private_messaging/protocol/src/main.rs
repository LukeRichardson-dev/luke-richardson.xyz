use std::vec;

use account::{CurrentUser, ForeignUser};
use encryption::{identity::Identity, account::ImplicitAccount};
use messages::{OutgoingMessage, IncomingMessage};
use openssl::{rsa::Rsa, pkey::PKey, dh::Dh, ec};

mod account;
mod messages;


fn main() {
    let message = "hello world".to_owned();

    let u1rsa = Rsa::generate(2048).unwrap();
    let user1 = ImplicitAccount {
        id: "user1".to_owned(),
        private_key: PKey::private_key_from_der(&u1rsa.private_key_to_der().unwrap()).unwrap(),
        public_key: PKey::public_key_from_der(&u1rsa.public_key_to_der().unwrap()).unwrap(),
        info: vec![],
    };

    let u2rsa = Rsa::generate(2048).unwrap();
    let user2 = ImplicitAccount {
        id: "user2".to_owned(),
        private_key: PKey::private_key_from_der(&u2rsa.private_key_to_der().unwrap()).unwrap(),
        public_key: PKey::public_key_from_der(&u2rsa.public_key_to_der().unwrap()).unwrap(),
        info: vec![],
    };

    let fuser2 = encryption::account::AmbiguousAccount { 
        id: "user2".to_owned(), 
        public_key: PKey::public_key_from_der(&u2rsa.public_key_to_der().unwrap()).unwrap(), 
        info: vec![], 
    };

    let message = OutgoingMessage {
        contents: message.as_bytes().to_vec(),
        to: fuser2,
        user: user1,
    };

    let mut payload = message.to_payload();

    let incoming = IncomingMessage::from_payload(payload.clone());
    println!("{:?}", incoming.verify());
    
    payload.contents.append(&mut vec![20u8; 1]);

    let incoming = IncomingMessage::from_payload(payload);
    println!("{:?}", incoming.verify());
}
