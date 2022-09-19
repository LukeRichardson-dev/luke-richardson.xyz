use encryption::identity::Identity;
use openssl::bn::BigNum;

pub type ID = String; // TODO

pub struct CurrentUser {

    pub identity: Identity<ID>,
    pub id: ID,

}

impl CurrentUser { }

pub struct ForeignUser {

    pub public_key: BigNum,
    pub id: ID

}