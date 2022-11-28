use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, SharedSecret};

// type HMAC = [u8];

// #[derive(Debug, Deserialize, Serialize)]
// struct Seal<T> 
//     where T: for<'a> Deserialize<'a> + Serialize {
//         data: T,
//         seal: HMAC,
// }

// impl Seal {
//     fn verify(&self, key: SharedSecret) -> bool {
        
//     }
// }

