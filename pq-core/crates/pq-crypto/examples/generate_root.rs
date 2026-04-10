use pq_crypto::SigningKeypair; fn main() { let kp = SigningKeypair::generate(); println!("{:?}", kp.public_key_bytes()); }
