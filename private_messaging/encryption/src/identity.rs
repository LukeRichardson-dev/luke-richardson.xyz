use std::collections::HashMap;
use openssl::bn::BigNum;
use openssl::dh::Dh;
use openssl::pkey::Private;

use crate::shared::{Shared, SharedBuilder};

struct Identity {
    key: Dh<Private>,
    shared_secrets: HashMap<String, Shared>,
}

impl Identity {
    pub fn new(key: Dh<Private>, shared_secrets: Option<HashMap<String, Shared>>) -> Self {
        Self {
            key,
            shared_secrets: shared_secrets.unwrap_or(HashMap::default()),
        }
    }

    pub fn create() -> Self {
        let key = Dh::get_2048_256().unwrap().generate_key().unwrap();

        Self { key, shared_secrets: HashMap::new() }
    }

    pub fn add_secret(&mut self, id: String, public_key: BigNum) -> &Shared {
        self.shared_secrets
            .entry(id)
            .or_insert_with(
                || SharedBuilder::new(public_key)
                    .generate_secret(self.key.private_key())
                    .unwrap().build()
            )
    }
}
