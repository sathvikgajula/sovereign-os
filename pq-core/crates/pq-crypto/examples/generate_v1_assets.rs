use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};
use pqcrypto_dilithium::dilithium3;
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
    let (pk, sk) = dilithium3::keypair();
    let pk_bytes = pk.as_bytes().to_vec();
    
    println!("ROOT_PUBLIC_KEY: {:?}", pk_bytes);

    let guards = vec![
        GuardNode {
            name: "FAU Research Lab".to_string(),
            endpoint: "fau.lab.pq-core.io:443".to_string(),
            pq_pk: "00".repeat(32), // Placeholder
        },
        GuardNode {
            name: "Galaxy Digital".to_string(),
            endpoint: "galaxy.digital.pq-core.io:443".to_string(),
            pq_pk: "00".repeat(32), // Placeholder
        },
    ];

    let mut manifest = Manifest {
        version: "1.0".to_string(),
        guards,
        signature: None,
    };

    let manifest_data = serde_json::to_vec(&manifest.guards).unwrap();
    let sig = dilithium3::detached_sign(&manifest_data, &sk);
    manifest.signature = Some(hex::encode(sig.as_bytes()));

    let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
    fs::write("manifest.json", manifest_json).unwrap();
    println!("Signed manifest.json created at manifest.json");
}
