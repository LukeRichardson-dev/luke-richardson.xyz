use std::cell::RefCell;
use std::rc::Rc;

use ring::aead::chacha20_poly1305_openssh::TAG_LEN;
use ring::aead::{NonceSequence, Nonce, NONCE_LEN, Algorithm, UnboundKey, SealingKey, BoundKey, Aad, OpeningKey, Tag};
use ring::error::Unspecified;
use x25519_dalek::SharedSecret;

#[derive(Clone)]
pub struct SymContext {

    counter: Rc<RefCell<u32>>,
    _alg: Rc<&'static Algorithm>,
    _key: Rc<[u8; 32]>,

}

impl SymContext {
    pub fn new(key: [u8; 32], alg: &'static Algorithm) -> Self {
        Self {
            counter: Rc::new(RefCell::new(0u32)),
            _key: Rc::new(key),
            _alg: Rc::new(alg),
        }
    }

    pub fn peek(&self) -> u32 {
        self.counter.borrow().clone()
    }

    pub fn key<T: BoundKey<Self>>(&self) -> T {
        BoundKey::new(UnboundKey::new(*self._alg, self._key.as_ref()).unwrap(), self.clone())
    }

    // !
    // TODO: enable AAD;
    // !

    pub fn encrypt<'a>(&mut self, payload: &'a mut Vec<u8>) {
        let mut bk: SealingKey<_> = self.key();
        bk.seal_in_place_append_tag(Aad::empty(), payload).unwrap();
    }

    pub fn decrypt<'a>(&mut self, payload: &'a mut Vec<u8>) 
        -> Result<&'a mut [u8], Unspecified> 
    {
        let mut bk: OpeningKey<_> = self.key();
        bk.open_in_place(Aad::empty(), payload)
    }
}

impl NonceSequence for SymContext {

    fn advance(&mut self) -> Result<Nonce, Unspecified> { // TODO: Just messy
        let mut nonce = [0u8; NONCE_LEN];
        for i in 0..4 {
            nonce[i] = (*self.counter.borrow() << (i * 8) & 0xFF) as u8;
        }
        *(*self.counter).borrow_mut() += 1;
        Ok(Nonce::assume_unique_for_key(nonce))
    }

}

