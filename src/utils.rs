use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hex;
use near_bigint::U256;
use num_bigint::BigUint;
use num_traits::Num;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::error::Error;

pub fn base64_url_to_base64(input: &str) -> String {
    let mut output = input.replace('-', "+").replace('_', "/");
    while output.len() % 4 != 0 {
        output.push('=');
    }
    output
}

pub fn hex_to_decimal(hex: &str) -> String {
    BigUint::from_str_radix(hex, 16).unwrap().to_str_radix(10)
}

pub fn convert_modulus(public_key_n: &str) -> Result<Vec<U256>, Box<dyn Error>> {
    let base64_n = base64_url_to_base64(public_key_n);
    let bytes = BASE64.decode(&base64_n)?;
    let hex_string = hex::encode(bytes);

    let mut result = Vec::new();
    let part_size = (hex_string.len() + 31) / 32; // 32 parts, each part 64 bits (16 hex chars)
    for i in 0..32 {
        let start = i * part_size;
        let end = std::cmp::min((i + 1) * part_size, hex_string.len());
        let part_hex = format!("{:0>16}", &hex_string[start..end]); // Pad to 16 characters (64 bits)
        let part_dec = hex_to_decimal(&part_hex);
        let part = U256::from_dec_str(&part_dec)?;
        result.push(part);
    }

    result.reverse();

    Ok(result)
}

pub fn hash_to_u256(input: &str) -> Result<Vec<U256>, Box<dyn Error>> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    let hex_string = hex::encode(result);
    let mut u256_vec = Vec::new();

    for i in 0..4 {
        // SHA-256 hash is 256 bits, so we need 4 U256 (64-bit each)
        let start = i * 16;
        let end = (i + 1) * 16;
        let part_hex = &hex_string[start..end];
        let part_dec = hex_to_decimal(part_hex);
        let part = U256::from_dec_str(&part_dec)?;
        u256_vec.push(part);
    }

    u256_vec.reverse();
    Ok(u256_vec)
}

pub fn decode_jwt_payload(
    jwt_parts: &str,
) -> Result<(String, String, String, String, u64), Box<dyn Error>> {
    let parts: Vec<&str> = jwt_parts.split('.').collect();
    if parts.len() < 2 {
        return Err("Invalid JWT format".into());
    }

    let payload = BASE64.decode(&base64_url_to_base64(parts[1]))?;
    let payload_str = String::from_utf8(payload)?;
    let json: Value = serde_json::from_str(&payload_str)?;

    let sub = json["sub"]
        .as_str()
        .ok_or("Missing 'sub' claim")?
        .to_string();
    let iss = json["iss"]
        .as_str()
        .ok_or("Missing 'iss' claim")?
        .to_string();
    let exp = json["exp"].as_u64().ok_or("Missing 'exp' claim")?;
    let email = json["email"]
        .as_str()
        .ok_or("Missing 'email' claim")?
        .to_string();
    let aud = json["aud"]
        .as_str()
        .ok_or("Missing 'aud' claim")?
        .to_string();

    Ok((sub, email, iss, aud, exp))
}
