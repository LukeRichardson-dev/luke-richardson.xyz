use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, PublicKey, ECDH_P256};

fn main() {
    println!("Hello, world!");
}

#[derive(Debug)]
struct Account {
    id: String,
    name: String,
    key: PublicKey,
}

impl Account {
    pub fn new(id: String, name: String, key: PublicKey) -> Self {
        Self { id, name, key }
    }

    fn secret(&self, private_key: EphemeralPrivateKey) {
        
        agree_ephemeral(private_key, self.key, (), ECDH_P256.into());

    }
}
