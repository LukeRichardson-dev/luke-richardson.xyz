use openssl::pkey::Private;
use openssl::ssl::{SslConnector, SslMethod, SslSession, Ssl};
use openssl::rsa::*;
use openssl::dh::Dh;
use openssl::base64::encode_block;

fn main() {
    
    diffie();

}

fn rsa_test() {
    let rsa: Rsa<Private> = Rsa::generate(2048).unwrap();
    rsa.public_key_to_pem().unwrap();
    let raw = b"Hello World";
    let mut buf = vec![0; rsa.size() as usize];
    rsa.private_encrypt(raw, &mut buf, Padding::PKCS1).unwrap();
    
    println!("{}", encode_block(&buf));
}

fn diffie() {
    let alice = Dh::get_2048_256().unwrap()
        .generate_key().unwrap();

    let bob = Dh::get_2048_256().unwrap()
        .generate_key().unwrap();

    let sh1 = alice.compute_key(bob.public_key()).unwrap();
    let sh2 = bob.compute_key(alice.public_key()).unwrap();

    println!("{}", encode_block(&sh1));
    println!("{}", encode_block(&sh2));
}


