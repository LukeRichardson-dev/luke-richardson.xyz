#[cfg(test)]
mod test {

    use idms::secure::sym::SymContext;
    use ring::aead::{CHACHA20_POLY1305, NonceSequence, AES_256_GCM};

    #[test]
    fn sym_context() {
        static PAYLOAD: [u8; 4] = [1, 2, 3, 4];

        let mut sc = SymContext::new([1u8; 32], &AES_256_GCM);
        let sc2 = sc.clone();
        assert_eq!(sc.peek(), sc2.peek());
        sc.advance().unwrap();
        assert_eq!(sc.peek(), sc2.peek());

        let mut payload: Vec<u8> = PAYLOAD.clone().to_vec();
        sc.encrypt(&mut payload);

        println!("{:?}, {:?}", PAYLOAD, payload);
        assert_ne!(payload, PAYLOAD);

        sc.decrypt(&mut payload).unwrap();
        
        println!("{:?}, {:?}", PAYLOAD, payload);
    }
}