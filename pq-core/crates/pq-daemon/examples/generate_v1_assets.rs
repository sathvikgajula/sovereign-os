use pq_crypto::SigningKeypair;
use serde::{Serialize, Deserialize};
use std::fs;

#[derive(Serialize, Deserialize)]
struct GuardNode {
    name: String,
    endpoint: String,
    pq_pk: String,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    version: String,
    guards: Vec<GuardNode>,
    signature: Option<String>,
}

fn main() {
    let kp = SigningKeypair::generate();
    let pk_bytes = kp.public_key_bytes();
    
    println!("ROOT_PUBLIC_KEY: {:?}", pk_bytes);

    let guards = vec![
        GuardNode {
            name: "FAU Research Lab".to_string(),
            endpoint: "fau.lab.pq-core.io:443".to_string(),
            pq_pk: hex::encode(vec![0xAA; 32]), // Placeholder for actual Guard PK
        },
        GuardNode {
            name: "Galaxy Digital".to_string(),
            endpoint: "galaxy.digital.pq-core.io:443".to_string(),
            pq_pk: hex::encode(vec![0xBB; 32]), // Placeholder for actual Guard PK
        },
    ];

    let mut manifest = Manifest {
        version: "1.0".to_string(),
        guards,
        signature: None,
    };

    let manifest_data = serde_json::to_vec(&manifest.guards).unwrap();
    let signature = kp.sign(&manifest_data);
    manifest.signature = Some(hex::encode(signature));

    let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
    fs::write("crates/pq-daemon/manifest.json", manifest_json).unwrap();
    println!("Signed manifest.json created at crates/pq-daemon/manifest.json");
}
