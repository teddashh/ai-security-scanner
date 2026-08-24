use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use minisign_verify::{PublicKey, Signature};
use std::fs;
use std::path::Path;

fn main() {
    if let Err(error) = run() {
        eprintln!("updater signature verification failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let encoded_public_key = arguments
        .next()
        .ok_or_else(|| "missing updater public key".to_owned())?;
    let remaining = arguments.collect::<Vec<_>>();
    if remaining.is_empty() || !remaining.len().is_multiple_of(2) {
        return Err("expected one or more payload/signature path pairs".into());
    }

    // Match tauri-plugin-updater exactly: tauri.conf stores an outer Base64
    // encoding of the complete minisign public-key document, and each `.sig`
    // contains an outer Base64 encoding of the complete signature document.
    let public_key_document = decode_utf8(&encoded_public_key, "public key")?;
    let public_key = PublicKey::decode(&public_key_document)
        .map_err(|error| format!("public key document is invalid: {error}"))?;

    let (pairs, remainder) = remaining.as_slice().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for [payload, signature] in pairs {
        let payload_path = Path::new(payload);
        let signature_path = Path::new(signature);
        let payload = fs::read(payload_path).map_err(|error| {
            format!(
                "could not read updater payload {}: {error}",
                payload_path.display()
            )
        })?;
        let encoded_signature = fs::read_to_string(signature_path).map_err(|error| {
            format!(
                "could not read updater signature {}: {error}",
                signature_path.display()
            )
        })?;
        let signature_document = decode_utf8(encoded_signature.trim(), "signature")?;
        let signature = Signature::decode(&signature_document)
            .map_err(|error| format!("signature document is invalid: {error}"))?;
        public_key
            .verify(&payload, &signature, true)
            .map_err(|error| {
                format!(
                    "{} does not verify against the embedded updater key: {error}",
                    payload_path.display()
                )
            })?;
    }
    Ok(())
}

fn decode_utf8(value: &str, label: &str) -> Result<String, String> {
    let decoded = BASE64
        .decode(value)
        .map_err(|_| format!("{label} is not valid outer Base64"))?;
    String::from_utf8(decoded).map_err(|_| format!("{label} document is not UTF-8"))
}
