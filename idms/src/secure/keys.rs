use std::cell::RefCell;
use std::rc::Rc;

use x25519_dalek::{PublicKey, EphemeralSecret, SharedSecret, StaticSecret};
use ring::aead::{SealingKey, UnboundKey, CHACHA20_POLY1305, BoundKey, Nonce, NONCE_LEN, NonceSequence, Algorithm};
use ring::rand::{generate, SystemRandom, SecureRandom};

use super::sym::SymContext;

const SHARED_SECRET_LENGTH: usize = 32;
static SYMM_ALG: &'static Algorithm = &CHACHA20_POLY1305;


pub struct SharedKey {
    secret: SharedSecret,
    _ctx: SymContext,
}

impl SharedKey {
    fn create_context(secret: &SharedSecret) -> SymContext {
        SymContext::new(
            secret.to_bytes(),
            SYMM_ALG,
        )
    }

    pub fn derive_eph(public: PublicKey, private: EphemeralSecret) -> Self {
        let secret = private.diffie_hellman(&public);
        let ctx = SymContext::new(secret.to_bytes(), SYMM_ALG);
        Self {
            secret,
            _ctx: ctx,
        }
    }

    pub fn derive_stat(public: PublicKey, private: StaticSecret) -> Self {
        let secret = private.diffie_hellman(&public);
        let ctx = SymContext::new(secret.to_bytes(), SYMM_ALG);
        Self {
            secret,
            _ctx: ctx,
        }
    }

    pub fn bytes(&self) -> [u8; SHARED_SECRET_LENGTH] {
        self.secret.to_bytes()
    }

    pub fn aes_key(&self) -> UnboundKey {
        UnboundKey::new(&CHACHA20_POLY1305, &self.bytes()).unwrap()
    }

    pub fn ctx(&self) -> SymContext {
        self._ctx.clone()
    }

}




