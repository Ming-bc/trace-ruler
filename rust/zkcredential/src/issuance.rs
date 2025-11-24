//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! The generation and verification of credential issuance proofs.
//!
//! When the issuing server issues a credential, it also generates a proof that the credential
//! covers the correct attributes. The client receives the proof and credential together, verifies
//! the proof, and extracts the credential. By providing the same attributes in the same order, the
//! generation and verification procedures have parallel invocations. The size of the proof scales
//! linearly with the number of attributes.
//!
//! Credential issuance is defined in Chase-Perrin-Zaverucha section 3.2.

// pub mod blind;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::BASEPOINT_ORDER;
use partial_default::PartialDefault;
use poksho::{ShoApi, ShoHmacSha256};
use serde::{Deserialize, Serialize};
use rand::rngs::OsRng;

use sha2::{Sha256, Digest};

use crate::attributes::{Attribute, PublicAttribute};
use crate::credentials::{
    Credential, CredentialKeyPair, CredentialPublicKey, SystemParams, NUM_SUPPORTED_ATTRS, OUR_SUPPORTED_ATTRS
};
use crate::sho::ShoExt;
use crate::{VerificationFailure, RANDOMNESS_LEN};

/// Contains a [`Credential`] along with a proof of its validity.
///
/// Use [`IssuanceProofBuilder`] to validate and extract the credential.
#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct IssuanceProof {
    pub credential: Credential,
    poksho_proof: Vec<u8>,
}

/// Used to generate and verify issuance proofs.
///
/// The same type is used for both generation and verification; the issuing server will end by
/// calling [`issue`](Self::issue) and the client by calling [`verify`](Self::verify).
pub struct IssuanceProofBuilder<'a> {
    public_attrs: ShoHmacSha256,
    /// Directly accessed by [`blind::BlindedIssuanceProofBuilder`].
    /// 
    /// attributes in [CMZ14] are elements in \mathbb{Z}_p 
    attr_scalars: Vec<Scalar>,
    authenticated_message: &'a [u8],
}

impl<'a> IssuanceProofBuilder<'a> {
    /// Initializes a new proof builder.
    ///
    /// `label` is a mandatory public attribute that should uniquely identify the credential.
    pub fn new(label: &[u8], attr: Scalar) -> Self {
        Self::with_authenticated_message(label, &[], attr)
    }

    /// Initializes the proof builder with a message that must match between the issuing server and
    /// the client.
    ///
    /// `label` is a mandatory public attribute that should uniquely identify the credential.
    /// `message`, however, is not an attribute and will not be part of the resulting credential; it
    /// is merely part of the proof. This could, for example, be used to distinguish multiple proofs
    /// that produce the same kind of credential.
    pub fn with_authenticated_message(label: &[u8], message: &'a [u8], attr: Scalar) -> Self {
        Self {
            public_attrs: ShoHmacSha256::new(label),
            // Reserve the first point for public attributes
            attr_scalars: vec![attr],
            authenticated_message: message,
        }
    }

    /// Adds a public attribute to the credential.
    ///
    /// This is order-sensitive.
    pub fn add_public_attribute(mut self, attr: &dyn PublicAttribute) -> Self {
        attr.hash_into(&mut self.public_attrs);
        self.public_attrs.ratchet();
        self
    }

    /// Adds an attribute to the credential.
    ///
    /// This is order-sensitive.
    // pub fn add_attribute(mut self, attr: &dyn Attribute) -> Self {
    //     self.attr_points.extend(attr.as_points());
    //     assert!(
    //         self.attr_points.len() <= NUM_SUPPORTED_ATTRS,
    //         "more than {} hidden attribute points not supported",
    //         NUM_SUPPORTED_ATTRS - 1
    //     );
    //     self
    // }

    // add attribute as scalar
    pub fn add_scalar_attribute(mut self, attr: Scalar){
        self.attr_scalars[0] = attr;
        self;
    }

    //  add the equations
    fn get_poksho_statement(&self) -> poksho::Statement {
        // See Chase-Perrin-Zaverucha section 3.2.
        let mut st = poksho::Statement::new();
        // U_Prime = (U ^ x0) + U^ (m * x1)
        st.add("U_Prime", &[("x0", "U"), ("x1", "U_m")]);
        // C_x0 = (g ^ x0) + (h ^ x2) 
        st.add("C_x0", &[("x0", "g"), ("x2", "h")]);
        // X1 = h ^ x1
        st.add("X1", &[("x1", "h")]);

        st
    }

    // fn finalize_public_attrs(&mut self) {
    //     debug_assert!(self.attr_points[0] == RistrettoPoint::identity());
    //     self.attr_points[0] = self.public_attrs.get_point();
    // }

        /// Generates a [`poksho::PointArgs`] to be used in the final proof.
    ///
    /// `total_attr_count` is passed in for [blind issuance](blind::BlindedIssuanceProofBuilder), in
    /// which case the caller may provide additional attributes.
    fn prepare_scalar_args(
        &self,
        key_pair: &CredentialKeyPair,
        total_attr_count: usize,
    ) -> poksho::ScalarArgs {
        assert!(
            total_attr_count <= NUM_SUPPORTED_ATTRS,
            "should have been enforced by the caller"
        );

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("x0", key_pair.private_key().x0);
        scalar_args.add("x1", key_pair.private_key().x1);
        scalar_args.add("x2", key_pair.private_key().x2);

        scalar_args
    }


    /// Generates a [`poksho::PointArgs`] to be used in the final proof.
    ///
    /// The `credential` argument may be `None` when used for [blind
    /// issuance](blind::BlindedIssuanceProofBuilder), in which case the caller is responsible for
    /// adding its own points representing the credential.
    fn prepare_point_args(
        &self,
        key: &CredentialPublicKey,
        total_attr_count: usize,
        credential: Option<&Credential>,
    ) -> poksho::PointArgs {
        let system = SystemParams::get_hardcoded();
        assert!(
            total_attr_count <= NUM_SUPPORTED_ATTRS,
            "should have been enforced by the caller"
        );

        let mut point_args = poksho::PointArgs::new();
        point_args.add("g", system.g);
        point_args.add("h", system.h);
        point_args.add("C_x0", key.C_x0);
        point_args.add("X1", key.X1);

        if let Some(credential) = credential {
            point_args.add("U", credential.U);
            point_args.add("U_Prime", credential.U_Prime);
            point_args.add("U_m", credential.U * self.attr_scalars[0]);
        }

        point_args
    }

    /// Issues a new credential over the accumulated attributes using the given `key_pair`.
    ///
    /// `randomness` ensures several important properties:
    /// - The generated credential is randomized (non-deterministic).
    /// - The issuance proof uses a random nonce.
    ///
    /// It is critical that different randomness is used each time a credential is issued. Failing
    /// to do so effectively reveals the server's private key.
    pub fn issue(
        mut self,
        key_pair: &CredentialKeyPair,
        randomness: [u8; RANDOMNESS_LEN],
    ) -> IssuanceProof {
        // self.finalize_public_attrs();

        let mut sho = ShoHmacSha256::new(b"Signal_ZKCredential_Issuance_20230410");
        sho.absorb_and_ratchet(&randomness);
        let credential = key_pair
            .private_key()
            .credential_core(&self.attr_scalars, &mut sho);

        let scalar_args = self.prepare_scalar_args(key_pair, self.attr_scalars.len());

        let point_args = self.prepare_point_args(
            key_pair.public_key(),
            self.attr_scalars.len(),
            Some(&credential),
        );
        let poksho_proof = self
            .get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                self.authenticated_message,
                &sho.squeeze_and_ratchet(RANDOMNESS_LEN)[..],
            )
            .unwrap();


        IssuanceProof {
            poksho_proof,
            credential,
        }
    }

    /// Verifies the given `proof` over the accrued attributes using the given `public_key`.
    ///
    pub fn verify(
        mut self,
        public_key: &CredentialPublicKey,
        proof: IssuanceProof,
    ) -> Result<Credential, VerificationFailure> {
        // self.finalize_public_attrs();
        let point_args =
            self.prepare_point_args(public_key, self.attr_scalars.len(), Some(&proof.credential));
        match self.get_poksho_statement().verify_proof(
            &proof.poksho_proof,
            &point_args,
            self.authenticated_message,
        ) {
            Err(_) => Err(VerificationFailure),
            Ok(_) => Ok(proof.credential),
        }
    }
}


#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;
    fn generate_random_scalar() -> Scalar {
        let seed = b"Signal_ZKCredential_ConstantSystemParams_generate_20230410";
        let mut hasher = Sha256::new();
        hasher.update(seed);
        let result = hasher.finalize();
        Scalar::from_bytes_mod_order(result.as_slice().try_into().expect("wrong length"))
    }
    #[test]
    fn test_proof(){ 
        let attr: u64 = 123;
        let attr = Scalar::from(attr);
        let builder = IssuanceProofBuilder::new("test".as_bytes(), attr);
        let key_pair = CredentialKeyPair::generate([0x42; RANDOMNESS_LEN]);

        let proof = builder.issue(&key_pair, [0x42; RANDOMNESS_LEN]);
        
        let builder = IssuanceProofBuilder::new("test".as_bytes(), attr);
        let result = builder.verify(&key_pair.public_key(), proof);
        assert!(result.is_ok());
        println!("Issuance proof and verification ok!");
    }

}