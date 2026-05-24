use zeroize::Zeroizing;

const ML_DSA_65_PK_LEN: usize = 1952;
const ML_DSA_65_SIG_LEN: usize = 3293;

static MANIFEST: &[u8] = include_bytes!("../manifest.json");

pub fn verify_boot_manifest_or_halt(
    signature_hex: &str,
    raw_pubkey: &[u8; ML_DSA_65_PK_LEN],
) -> Result<(), &'static str> {
    if signature_hex.len() != ML_DSA_65_SIG_LEN * 2 {
        return Err("signature hex length does not match ML-DSA-65 output size");
    }

    let mut sig_buf = Zeroizing::new([0u8; ML_DSA_65_SIG_LEN]);

    hex::decode_to_slice(signature_hex, &mut sig_buf[..])
        .map_err(|_| "failed to decode signature hex into stack buffer")?;

    pqc::verify_signature(MANIFEST, &sig_buf[..], &raw_pubkey[..])
        .map_err(|_| "ML-DSA-65 boot manifest verification failed — halting")?;

    Ok(())
}
