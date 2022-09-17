use openssl::bn::BigNum;

struct Identity {

    pub_key: BigNum,
    priv_key: BigNum,

}

impl Identity {
    
    pub fn new(pub_key: BigNum, priv_key: BigNum) -> Self {

        Self { pub_key, priv_key }

    }

}