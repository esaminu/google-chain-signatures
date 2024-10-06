use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hex;
use near_bigint::U256;
use near_groth16_verifier::{Proof, Verifier};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, near_bindgen, serde_json::json, Gas, PanicOnDefault, Promise};
use num_bigint::BigUint;
use num_traits::Num;
use serde_json::Value;
use serde_json_canonicalizer::to_string as to_canonical_json;
use sha2::{Digest, Sha256};

fn base64_url_to_base64(input: &str) -> String {
    let mut output = input.replace('-', "+").replace('_', "/");
    while output.len() % 4 != 0 {
        output.push('=');
    }
    output
}

fn hex_to_decimal(hex: &str) -> String {
    BigUint::from_str_radix(hex, 16).unwrap().to_str_radix(10)
}

fn convert_modulus(public_key_n: &str) -> Result<Vec<U256>, Box<dyn std::error::Error>> {
    let base64_n = base64_url_to_base64(public_key_n);
    let bytes = BASE64.decode(&base64_n)?;
    let hex_string = hex::encode(bytes);

    // Convert hex string to Vec<U256>
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

    // Reverse the order of the U256 values
    result.reverse();

    Ok(result)
}

fn hash_to_u256(input: &str) -> Result<Vec<U256>, Box<dyn std::error::Error>> {
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

fn decode_jwt_payload(
    jwt_parts: &str,
) -> Result<(String, String, String, String, u64), Box<dyn std::error::Error>> {
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

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct Meta {
    email: String,
    aud: String,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct DerivationPath {
    chain: String,
    meta: Meta,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct SignRequest {
    pub payload: [u8; 32],
    pub path: String,
    pub key_version: u32,
}

#[near_bindgen]
#[derive(PanicOnDefault, BorshDeserialize, BorshSerialize)]
pub struct Contract {
    pub verifier: Verifier,
    moduli: Vec<Vec<U256>>,
}

/**
 * [x] 1. Confirm the public key modulus is the same as modulus input
 * [x] 2. Regenerate message hash from message argument and verify
 * [x] 3. Extract sub and issuer from message
 * [x] 4. sign_with_google_token(proof, public_inputs, message, chain, payload)
 * [x] 5. Change google keys to cron job pushing an array of ns that get converted to Vec<U256> and stored in state (Can only be called by 1 account for now)
 */

#[near_bindgen]
impl Contract {
    #[init]
    pub fn new(verifier: Verifier) -> Self {
        assert!(!env::state_exists(), "Already initialized");
        Self {
            verifier,
            moduli: Vec::new(),
        }
    }

    #[payable]
    pub fn sign_with_google_token(
        &mut self,
        proof: Proof,
        public_inputs: Vec<U256>,
        message: String,
        chain: String,
        payload: [u8; 32],
    ) -> Promise {
        let verification_result = self.verifier.verify(public_inputs.clone(), proof);
        assert!(verification_result, "Verification failed");

        // assert_eq!(&public_inputs[32..64], Self::get_google_public_key(), "Public key modulus does not match");

        let public_key_modulus = &public_inputs[32..64];
        assert!(
            self.moduli
                .iter()
                .any(|modulus| modulus == public_key_modulus),
            "Public key modulus does not match any known Google public key"
        );

        let message_hash_u256 = hash_to_u256(&message).expect("Failed to hash message");
        assert_eq!(
            &public_inputs[64..68],
            message_hash_u256,
            "Message hash does not match"
        );

        let (_sub, email, iss, aud, exp) =
            decode_jwt_payload(&message).expect("Failed to decode JWT payload");
        assert_eq!(iss, "https://accounts.google.com", "Invalid issuer");
        assert_eq!(
            exp > env::block_timestamp() / 1_000_000_000,
            true,
            "Token expired"
        ); // temp false for testing

        let path = DerivationPath {
            chain,
            meta: Meta { email, aud },
        };

        let canonical_path =
            to_canonical_json(&path).expect("Failed to serialize path to canonical JSON");

        let request = SignRequest {
            payload,
            path: canonical_path,
            key_version: 0,
        };

        let args = json!({
            "request": request
        });

        let deposit = env::attached_deposit();
        const TGAS: u64 = 1_000_000_000_000;
        const GAS_FOR_MPC_CALL: Gas = Gas(100 * TGAS);

        Promise::new("v1.signer-prod.testnet".parse().unwrap()).function_call(
            "sign".to_string(),
            near_sdk::serde_json::to_vec(&args).unwrap(),
            deposit,
            GAS_FOR_MPC_CALL,
        )
    }

    pub fn update_moduli(&mut self, new_moduli: Vec<String>) {
        assert_eq!(
            env::predecessor_account_id(),
            env::current_account_id(),
            "Only the contract account can update moduli"
        );

        let converted_moduli: Vec<Vec<U256>> = new_moduli
            .into_iter()
            .map(|modulus_str| {
                convert_modulus(&modulus_str).expect("Failed to convert modulus. Aborting update.")
            })
            .collect();

        self.moduli = converted_moduli;
    }

    // #[private]
    // fn get_google_public_key() -> Vec<U256> {
    //     let public_key_n =
    //     "1BqxSPBr-Fap-E39TLXfuDg0Bfg05zYqhvVvEVhfPXRkPj7M8uK_1MOb-11XKaZ4IkWMJIwRJlT7DvDqpktDLxvTkL5Z5CLkX63TzDMK1LL2AK36sSqPthy1FTDNmDMry867pfjy_tktKjsI_lC40IKZwmVXEqGS2vl7c8URQVgbpXwRDKSr_WKIR7IIB-FMNaNWC3ugWYkLW-37zcqwd0uDrDQSJ9oPX0HkPKq99Imjhsot4x5i6rtLSQgSD7Q3lq1kvcEu6i4KhG4pA0yRZQmGCr4pzi7udG7eKTMYyJiq5HoFA446fdk6v0mWs9C7Cl3R_G45S_dH0M8dxR_zPQ";

    //     convert_modulus(public_key_n).expect("Failed to convert modulus")

    // }
}
