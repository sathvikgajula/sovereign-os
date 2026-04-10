use pqc::SigningKeypair;
use std::fs;

fn main() {
    let kp = SigningKeypair::generate();
    let pk = kp.public_key_bytes();
    fs::write("root_pk.bin", &pk).unwrap();
    println!("SUCCESS");
}
