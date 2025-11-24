use apple_psi::{apple_psi::INPUT_LENGTH, RANDOMNESS_LEN};
use curve25519_dalek::Scalar;
use rand::Rng;
use sha2::{digest::Update, Digest, Sha256, Sha512};
use zkcredential::{credentials::{Credential, CredentialPublicKey}, issuance::{IssuanceProof, IssuanceProofBuilder}, presentation::{PresentationProof, PresentationProofBuilder}};
use std::fmt;

#[derive(Clone)]
pub struct User{
    pub uid: u64,
    pub k_u: Scalar,
    pub z: Option<Scalar>,
    pub cred: Option<IssuanceProof>,
}

impl User {
    pub fn new() -> Self{
        let uid = rand::thread_rng().gen::<u64>();
        let attr = User::hash_uid(uid);
        Self{
            uid,
            k_u: attr,
            z: None,
            cred: None,
        }
    }

    pub fn hash_uid(uid: u64) ->Scalar{
        let mut hasher = Sha512::new().chain(uid.to_le_bytes());
        Scalar::from_hash(hasher)
    }

    pub fn verify_credential_proof(&self, pk:&CredentialPublicKey, proof: IssuanceProof) -> bool{
        let builder = IssuanceProofBuilder::new(b"user_proof", self.k_u);
        let result = builder.verify(pk, proof);
        result.is_ok()
    }

    pub fn present(&self, pk:&CredentialPublicKey, credential: &Credential, randomness:[u8;RANDOMNESS_LEN]) -> (PresentationProof, Scalar, Scalar){
        let builder = PresentationProofBuilder::new(b"user_present", self.k_u);
        builder.present(pk, credential, randomness)
    }

    pub fn set_k_u(&mut self, k_u: Scalar){
        self.k_u = k_u;
    }

    pub fn update_z(&mut self, new_z: Scalar) {
        self.z = Some(new_z);
    }

    pub fn set_cred(&mut self, cred: IssuanceProof){
        self.cred = Some(cred);
    }
}