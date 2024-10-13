use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::AccountId;
use near_sdk::{env, near_bindgen, serde_json::json, Gas, PanicOnDefault, Promise};
use near_groth16_verifier::{Proof, Verifier};
use near_bigint::U256;
use serde_json_canonicalizer::to_string as to_canonical_json;

mod utils;
mod models;

use utils::{hash_to_u256, decode_jwt_payload, convert_modulus};
use models::{SignRequest, DerivationPath, Meta};

#[near_bindgen]
#[derive(PanicOnDefault, BorshDeserialize, BorshSerialize)]
pub struct Contract {
    pub verifier: Verifier,
    moduli: Vec<Vec<U256>>,
    signer_contract_id: AccountId
}

#[near_bindgen]
impl Contract {
    #[init]
    pub fn new(verifier: Verifier, signer_contract_id: AccountId) -> Self {
        assert!(!env::state_exists(), "Already initialized");
        Self {
            verifier,
            moduli: Vec::new(),
            signer_contract_id
        }
    }

    pub fn reinitialize(&mut self, verifier: Verifier, signer_contract_id: AccountId) {
        assert_eq!(
            env::predecessor_account_id(),
            env::current_account_id(),
            "Only the contract account can reinitialize"
        );

        self.verifier = verifier;
        self.signer_contract_id = signer_contract_id;
    }

    #[payable]
    pub fn sign_with_google_token(
        &mut self,
        proof: Proof,
        public_inputs: Vec<U256>,
        message: String,
        chain: u64,
        payload: [u8; 32],
    ) -> Promise {
        let verification_result = self.verifier.verify(public_inputs.clone(), proof);
        assert!(verification_result, "Verification failed");

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

        Promise::new(self.signer_contract_id.clone()).function_call(
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
}
