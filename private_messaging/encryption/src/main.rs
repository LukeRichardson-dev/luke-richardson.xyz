use openssl::pkey::Private;
use openssl::rsa::*;
use openssl::dh::Dh;
use openssl::base64::encode_block;
use shared::SharedBuilder;

pub mod identity;
pub mod shared;

fn main() {

    let alice = Dh::get_2048_256().unwrap()
        .generate_key().unwrap();
    let bob = Dh::get_2048_256().unwrap()
        .generate_key().unwrap();
    
    let mut shared = SharedBuilder::new(alice.public_key().to_owned().unwrap())
        .generate_secret(bob.private_key()).unwrap()
        .build();

    let data = b"hello world";
    println!("{:?}", data);

    match shared.encrypt(data.to_vec()) {
        Ok(enc) => println!(
            "{:?}\n{:?}", 
            enc.clone(),
            String::from_utf8(shared.decrypt(enc).unwrap()).unwrap()
        ),
        Err(err) => println!("{:?}", err),
    }

}

#[allow(unused)]
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


