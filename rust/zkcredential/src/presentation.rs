//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! The generation and verification of credential presentation proofs
//!
//! When the client wishes to use a credential, it generates a _presentation proof_ over the same
//! attributes that went into the original credential. This allows the client to demonstrate that
//! they hold a credential over certain attributes without actually revealing those attributes. The
//! verifying server will verify the proof against the encrypted forms of those attributes and is
//! thus assured that the client does hold a credential from the issuing server.
//!
//! By providing the same attributes in the same order, a proof can be generated and verified with
//! parallel invocations. The size of the proof scales linearly with the number of attributes.
//!
//! It is recommended that the client generate a new presentation for every use of their private
//! credential, so that the verifying server cannot track repeated uses of the same presentation. Of
//! course, the encrypted forms of the attributes might also allow the verifying server to correlate
//! requests over time.
//!
//! Credential presentation is defined in Chase-Perrin-Zaverucha section 3.2; proofs for verifiable
//! encryption are defined in section 4.1.

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::Scalar;
use partial_default::PartialDefault;
use poksho::{ShoApi, ShoHmacSha256};
use serde::{Deserialize, Serialize};

use crate::attributes::{self, Attribute, PublicAttribute, RevealedAttribute};
use crate::credentials::{
    Credential, CredentialKeyPair, CredentialPrivateKey, CredentialPublicKey, SystemParams,
    NUM_SUPPORTED_ATTRS,
};
use crate::issuance::{self, IssuanceProofBuilder, IssuanceProof};
use crate::sho::ShoExt;
use crate::{VerificationFailure, RANDOMNESS_LEN};

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct PresentationProofCommitments { // TODO: change to C_m, C_U_Prime do not need to generate proof
    C_m: RistrettoPoint,
    // C_U_Prime: RistrettoPoint,
}

/// Demonstrates to the _verifying server_ that the client holds a particular credential.
///
/// Use [`PresentationProofVerifier`] to validate the proof.
#[derive(Serialize, Deserialize, PartialDefault, Clone)]
pub struct PresentationProof {
    pub u: RistrettoPoint,
    pub C_m: RistrettoPoint,
    pub C_U_Prime: RistrettoPoint,
    poksho_proof: Vec<u8>,
}

impl PresentationProof {
    pub fn get_omega_bytes(&self) -> Vec<u8>{
        let u_bytes: [u8; 32] = self.u.compress().to_bytes();
        let C_m_bytes: [u8; 32] = self.C_m.compress().to_bytes();
        let C_U_Prime_bytes: [u8; 32] = self.C_U_Prime.compress().to_bytes();

        [u_bytes.as_ref(), C_m_bytes.as_ref(), C_U_Prime_bytes.as_ref()].concat()
    }
}

struct AttributeRef {
    key_index: Option<usize>,
    first_point_index: usize,
    second_point_index: usize,
}

struct PresentationProofBuilderCore<'a> { // TODO: add attr_scalar
    attributes: Vec<AttributeRef>,
    attr_points: Vec<RistrettoPoint>,
    attr_scalars: Vec<Scalar>,
    authenticated_message: &'a [u8],
}

/// Used to generate presentation proofs.
///
/// Public attributes are not included from the presentation proof; when the proof is verified, the
/// verifying server will provide its own copy of the public attributes to ensure that they haven't
/// been tampered with.
///
/// See also [`PresentationProofVerifier`].
pub struct PresentationProofBuilder<'a> {
    core: PresentationProofBuilderCore<'a>,
}

/// Used to verify presentation proofs.
///
/// By providing the same attributes in the same order, a proof can be generated and verified with
/// parallel invocations. The size of the proof scales linearly with the number of attributes.
///
/// Public attributes are not included from the presentation proof; when the proof is verified, the
/// verifying server will provide its own copy of the public attributes to ensure that they haven't
/// been tampered with, as mentioned in Chase-Perrin-Zaverucha section 3.2.
///
/// See also [`PresentationProofBuilder`].
pub struct PresentationProofVerifier<'a> {
    core: PresentationProofBuilderCore<'a>,
    public_attrs: ShoHmacSha256,
}

impl<'a> PresentationProofBuilderCore<'a> {
    fn with_authenticated_message(message: &'a [u8], attr: Scalar) -> Self {
        Self {
            attributes: vec![],
            // Reserve the first point for public attributes
            attr_points: vec![RistrettoPoint::identity()],
            attr_scalars: vec![attr],
            authenticated_message: message,
        }
    }


    fn get_poksho_statement(&self) -> poksho::Statement {
        let mut st = poksho::Statement::new();
        // These terms are from Chase-Perrin-Zaverucha section 3.2.
        st.add("C_m", &[("m", "U"), ("z", "h")]);
        st.add("V", &[("-r", "g"), ("z", "X1")]);

        st
    }

    /// Generates [`poksho::PointArgs`] containing all points not derived from attributes.
    ///
    /// This includes the credential key commitments `C_x0`, `C_x1`, and `C_y0`; the system points
    /// `G_x0`, `G_x1`, and all `G_y{i}`; the appropriate issuing parameter point `I`; and the
    /// points necessary to prove the validity of encryption keys: `0`, `G_a1_{key}`, `G_a2_{key}`,
    /// and `sum(A)`.
    ///
    /// The caller is responsible for handling the presenter's one-off public point `Z` (which the
    /// verifier derives from the commitments and public attributes); the appropriate `C_y{i}` for
    /// all attributes besides public attributes (depending on whether or not attributes are
    /// encrypted); and the encryption-specific points `E_A{i}`, `-E_A{i}`, and `C_y{j}-E_A{j}`.
    fn prepare_non_attribute_point_args(
        &self,
        key: &CredentialPublicKey,
        commitments: &RistrettoPoint,
    ) -> poksho::PointArgs {
        let credentials_system = SystemParams::get_hardcoded();

        let mut point_args = poksho::PointArgs::new();

        //point_args.add("C_U_Prime", commitments.C_U_Prime);
        point_args.add("C_m", *commitments);
        point_args.add("g", credentials_system.g);
        point_args.add("h", credentials_system.h);
        point_args.add("X1", key.X1);
        // Other C_y depend on the form of the attribute.
        point_args
    }
}

impl<'a> PresentationProofBuilder<'a> {
    /// Initializes a new proof builder.
    ///
    /// `label` is a mandatory public attribute that should uniquely identify the credential, but as
    /// a public attribute it is ignored. It is merely here for symmetry with
    /// [`PresentationProofVerifier::new`].
    pub fn new(label: &[u8], attr: Scalar) -> Self {
        Self::with_authenticated_message(label, &[], attr)
    }

    /// Initializes a new proof builder.
    ///
    /// `label` is a mandatory public attribute that should uniquely identify the credential, but as
    /// a public attribute it is ignored. It is merely here for symmetry with
    /// [`PresentationProofVerifier::with_authenticated_message`].
    ///
    /// `message`, however, is not an attribute and is not part of the original credential; it is
    /// merely part of the proof. This could, for example, be used to distinguish multiple proofs
    /// that present the same kind of credential.
    pub fn with_authenticated_message(label: &[u8], message: &'a [u8], attr: Scalar) -> Self {
        _ = label;
        Self {
            core: PresentationProofBuilderCore::with_authenticated_message(message, attr),
        }
    }

    /// Unnecessary: public attributes are passed directly to the verifying server.
    #[deprecated = "Unnecessary: public attributes are passed directly to the verifying server."]
    pub fn add_public_attribute(self, attr: &dyn PublicAttribute) -> Self {
        _ = attr;
        self
    }

    /// Generates the presentation of `credential` using the server-provided `public_key`.
    ///
    /// Note that this does not consume `credential`; indeed, it is recommended to use a new
    /// presentation every time you want to use a particular credential.
    ///
    /// `randomness` ensures several important properties:
    /// - The generated presentation is randomized (non-deterministic).
    /// - The presentation proof uses a random nonce.
    ///
    /// It is critical that different randomness is used each time a credential is issued. Failing
    /// to do so allows different presentations to be linked to the same credential (and thus the
    /// same user), and worse, effectively reveals any hidden Attributes and their encryption keys.
    pub fn present(
        self,
        public_key: &CredentialPublicKey,
        credential: &Credential,
        randomness: [u8; RANDOMNESS_LEN],
    ) -> (PresentationProof, Scalar, Scalar) {
        let credentials_system = SystemParams::get_hardcoded();

        let mut sho = ShoHmacSha256::new(b"Signal_ZKCredential_Presentation_20230410");
        sho.absorb_and_ratchet(&randomness);
        let z = sho.get_scalar();
        let r = sho.get_scalar();

        // Note that Mn will be the identity element for both the first point and for any
        // RevealedAttributes, so this will simply produce `z * G_yn` for those elements as in
        // Chase-Perrin-Zaverucha section 3.2.
        // C_m = h^z + U^m
        let C_m = (z * credentials_system.h) + (credential.U * self.core.attr_scalars[0]);
        // C_U_prime = U_Prime + g ^ r
        let C_U_Prime = credential.U_Prime + (credentials_system.g * r);
        // V = g^(-r) + X1 ^ z
        let V = (credentials_system.g * (-r)) + (public_key.X1 * z);

        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("z", z);
        scalar_args.add("-r", -r);
        scalar_args.add("m", self.core.attr_scalars[0]);

        let mut point_args = self.core.prepare_non_attribute_point_args(public_key, &C_m);
        point_args.add("V", V);
        point_args.add("U", credential.U);

        let poksho_proof = self
            .core
            .get_poksho_statement()
            .prove(
                &scalar_args,
                &point_args,
                self.core.authenticated_message,
                &sho.squeeze_and_ratchet(RANDOMNESS_LEN)[..],
            )
            .unwrap();

        // let res = self.core.get_poksho_statement().verify_proof(&poksho_proof, &point_args, &self.core.authenticated_message);
        // assert!(res.is_ok());
        let u = credential.U;
        let presendation_proof = PresentationProof {
            u,
            C_m,
            C_U_Prime,
            poksho_proof,
        };
        (presendation_proof, z, r)
    }
}

impl<'a> PresentationProofVerifier<'a> {
    /// Initializes a new proof verifier.
    ///
    /// `label` is a mandatory public attribute that should uniquely identify the credential.
    pub fn new(label: &[u8], attr :Scalar) -> Self {
        Self::with_authenticated_message(label, &[], attr)
    }

    /// Initializes a new proof verifier.
    ///
    /// `label` is a mandatory public attribute that should uniquely identify the credential.
    /// `message`, however, is not an attribute and is not part of the original credential; it is
    /// merely part of the proof. This could, for example, be used to distinguish multiple proofs
    /// that present the same kind of credential.
    pub fn with_authenticated_message(label: &[u8], message: &'a [u8], attr: Scalar) -> Self {
        Self {
            core: PresentationProofBuilderCore::with_authenticated_message(message, attr),
            public_attrs: ShoHmacSha256::new(label),
        }
    }

    /// Adds a public attribute to check against the credential.
    ///
    /// This is order-sensitive.
    pub fn add_public_attribute(mut self, attr: &dyn PublicAttribute) -> Self {
        attr.hash_into(&mut self.public_attrs);
        self.public_attrs.ratchet();
        self
    }

    fn finalize_public_attrs(&mut self) {
        debug_assert!(self.core.attr_points[0] == RistrettoPoint::identity());
        self.core.attr_points[0] = self.public_attrs.get_point();
    }

    /// Verifies the given `proof` over the accrued attributes using the given `key_pair`.
    pub fn verify(
        mut self,
        key_pair: &CredentialKeyPair,
        proof: &PresentationProof,
    ) -> Result<(), VerificationFailure> {
        self.finalize_public_attrs();


        let CredentialPrivateKey { x0, x1, x2 } = key_pair.private_key();

        // Z = (u * x0 + C_m * x1) - C_U_Prime
        let mut V = (proof.u * x0 + &proof.C_m * x1) - proof.C_U_Prime;

        let mut point_args = self
            .core
            .prepare_non_attribute_point_args(key_pair.public_key(), &proof.C_m);
        point_args.add("V", V);
        point_args.add("U", proof.u);

        match self.core.get_poksho_statement().verify_proof(
            &proof.poksho_proof,
            &point_args,
            self.core.authenticated_message,
        ) {
            Err(_) => Err(VerificationFailure),
            Ok(_) => Ok(()),
        }
    }
}


#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::*;

    #[test]
    fn test_proof(){ 
        let attr: u64 = 123;
        let attr = Scalar::from(attr);
        let issuance_builder = IssuanceProofBuilder::new("test".as_bytes(), attr.clone());
        let builder = PresentationProofBuilder::new("test_builder".as_bytes(), attr.clone());
        let verifier = PresentationProofVerifier::new("test_builder".as_bytes(), attr.clone());
        let key_pair = CredentialKeyPair::generate([0x42; RANDOMNESS_LEN]);

        let issuance_proof = issuance_builder.issue(&key_pair, [0x42; RANDOMNESS_LEN]);
        let credential = issuance_proof.credential;
        let (presentation_proof, z, r) = builder.present(key_pair.public_key(), &credential, [0x42; RANDOMNESS_LEN]);
        let result = verifier.verify(&key_pair, &presentation_proof);

        assert!(result.is_ok());
    }

}