use std::{collections::HashMap, sync::Arc};

use apple_psi::{apple_psi::server, RANDOMNESS_LEN};
use zkcredential::{credentials::{CredentialKeyPair, CredentialPublicKey}, issuance::{IssuanceProof, IssuanceProofBuilder}, presentation::{PresentationProof, PresentationProofVerifier}};
use curve25519_dalek::{scalar::Scalar, RistrettoPoint};
use boring::ecdsa::EcdsaSig;

#[derive(Clone)]
pub struct Platform<'a>{
    cred_keypair: CredentialKeyPair,
    pub s: server<'a>,
    pub hash_map: HashMap<[u8;32], u64>,
}

impl<'a> Platform<'a> {
    pub fn new(randomness: [u8;RANDOMNESS_LEN]) -> Self{
        let cred_keypair = CredentialKeyPair::generate(randomness);
        let s = server::new(b"platform", &randomness);
        let hash_map = HashMap::new();
        Self{
            cred_keypair,
            s,
            hash_map,
        }
    }

    pub fn issue(&self, attr: Scalar, randomness: [u8;RANDOMNESS_LEN]) -> IssuanceProof{
        let builder = IssuanceProofBuilder::new(b"user_proof", attr);
        let proof = builder.issue(&self.cred_keypair, randomness);
        proof
    }

    pub fn get_cred_pk(&self) -> &CredentialPublicKey{
        let pk = self.cred_keypair.public_key();
        &pk
    }

    pub fn verify_presentation_proof(&self, presentation_proof: &PresentationProof, attr: Scalar) -> bool {
        let verifier = PresentationProofVerifier::new(b"user_present", attr.clone());
        verifier.verify(&self.cred_keypair, presentation_proof).is_ok()
    }

    pub fn sign(&self, msg: &[u8]) -> EcdsaSig{
        self.s.sign_ecdsa(msg)
    }

    pub fn verify(&self, msg: &[u8], sig: &EcdsaSig) -> bool{
        self.s.verify_ecdsa(msg, sig)
    }

    pub fn insert_to_hashmap(&mut self, k_u: &[u8;32], v: u64){
        self.hash_map.insert(*k_u, v);
    }

    pub fn find_uid(&self, k_u: &[u8;32]) -> Option<&u64>{
        self.hash_map.get(k_u)
    }
}