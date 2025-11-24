//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Types used in both the issuance and presentation of credentials

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::constants::BASEPOINT_ORDER;

use sha2::{Sha256, Digest};
use lazy_static::lazy_static;
use partial_default::PartialDefault;
use poksho::{ShoApi, ShoHmacSha256, ShoSha256};
use serde::{Deserialize, Serialize};

use crate::sho::ShoExt;
use crate::RANDOMNESS_LEN;

/// A credential created by the issuing server over a set of attributes.
///
/// Defined in Chase-Perrin-Zaverucha section 3.1.
#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct Credential {
    pub U: RistrettoPoint,
    pub U_Prime: RistrettoPoint,
}

/// A secret key used to compute a MAC over a set of attributes
///
/// Defined in Chase-Perrin-Zaverucha section 3.1.
#[derive(Serialize, Deserialize, Clone, PartialDefault)]
pub(crate) struct CredentialPrivateKey {
    pub(crate) x0: Scalar,
    pub(crate) x1: Scalar,
    pub(crate) x2: Scalar,
}

impl CredentialPrivateKey {
    /// Creates a new secret key using the given source of random bytes.
    fn generate(randomness: [u8; RANDOMNESS_LEN]) -> Self {
        let mut sho = ShoHmacSha256::new(b"Signal_ZKCredential_CredentialPrivateKey_generate_20230410");
        sho.absorb_and_ratchet(&randomness);

        let system = *SYSTEM_PARAMS;
        let x0 = sho.get_scalar();
        let x1 = sho.get_scalar();
        let x2 = sho.get_scalar();
        Self {
            x0,
            x1,
            x2,
        }
    }

    /// Produces a MAC over the given attributes.
    ///
    /// Implements the credential computation described in Chase-Perrin-Zaverucha section 3.1.
    ///
    /// # Panics
    /// if more than [`NUM_SUPPORTED_ATTRS`] attributes are passed in.
    pub(crate) fn credential_core(&self, M: &[Scalar], sho: &mut dyn ShoApi) -> Credential {

        assert!(
            M.len() <= OUR_SUPPORTED_ATTRS,
            "more than {} attributes not supported",
            OUR_SUPPORTED_ATTRS
        );
        
        // U = random point
        let U = sho.get_point();
        // U' = U * (x0 + x1 * m)
        let U_Prime = U * (self.x0 + self.x1 * M[0]);
        Credential { U, U_Prime }
    }
}

/// A public key used by the client to receive and verify credentials.
///
/// Defined in Chase-Perrin-Zaverucha section 3.1.
#[derive(Serialize, Deserialize, Clone, PartialDefault)]
pub struct CredentialPublicKey {
    pub C_x0: RistrettoPoint,
    pub X1: RistrettoPoint,
}

impl<'a> From<&'a CredentialPrivateKey> for CredentialPublicKey {
    fn from(private_key: &'a CredentialPrivateKey) -> Self {
        let system = *SYSTEM_PARAMS;
        
        // C_x0 = (g ^ x0) + (h ^ x2)
        let C_x0 = (system.g * private_key.x0) + (system.h * private_key.x2);
        // X1 = h ^ x1
        let X1 = system.h * private_key.x1;

        CredentialPublicKey {C_x0, X1 }
    }
}

/// A key pair used by the issuing server to sign credentials.
///
/// Defined in Chase-Perrin-Zaverucha section 3.1.
#[derive(Deserialize, Clone, PartialDefault)]
#[serde(from = "CredentialPrivateKey")]
pub struct CredentialKeyPair {
    private_key: CredentialPrivateKey,
    public_key: CredentialPublicKey,
}

impl CredentialKeyPair {
    /// Generates a new key pair.
    pub fn generate(randomness: [u8; RANDOMNESS_LEN]) -> Self {
        CredentialPrivateKey::generate(randomness).into()
    }

    pub(crate) fn private_key(&self) -> &CredentialPrivateKey {
        &self.private_key
    }

    /// Gets the public key.
    pub fn public_key(&self) -> &CredentialPublicKey {
        &self.public_key
    }
}

impl From<CredentialPrivateKey> for CredentialKeyPair {
    fn from(private_key: CredentialPrivateKey) -> Self {
        let public_key = CredentialPublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }
}

impl Serialize for CredentialKeyPair {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.private_key.serialize(serializer)
    }
}

lazy_static! {
    static ref SYSTEM_PARAMS: SystemParams = SystemParams::generate();
}

pub(crate) const NUM_SUPPORTED_ATTRS: usize = 7; // 2 attributes
pub(crate) const OUR_SUPPORTED_ATTRS: usize = 2; // 2 attributes

/// Parameters shared by the client and server.
///
/// User code never needs to explicitly reference these.
///
/// Defined in Chase-Perrin-Zaverucha section 3.1.
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct SystemParams {
    pub p: Scalar, //group order
    pub g: RistrettoPoint, // generator g
    pub h: RistrettoPoint, // generator h
}

impl SystemParams {
    /// An arbitrary set of independent points generated through a constant sequence of hash
    /// operations.
    pub fn generate() -> Self {
        let mut sho = ShoSha256::new(b"Signal_ZKCredential_ConstantSystemParams_generate_20230410");
        let p = BASEPOINT_ORDER;
        let g = RISTRETTO_BASEPOINT_POINT;
        
        // use fixed seed to genarate "h"
        let seed = b"Signal_ZKCredential_ConstantSystemParams_generate_20230410";
        let mut hasher = Sha256::new();
        hasher.update(seed);
        let result = hasher.finalize();
        let h_seed = Scalar::from_bytes_mod_order(result.as_slice().try_into().expect("wrong length"));
        let h = h_seed * g;

        SystemParams {
            p,
            g,
            h,
        }
    }

    pub fn get_hardcoded() -> SystemParams {
        *SYSTEM_PARAMS
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    impl SystemParams {
        //const SYSTEM_HARDCODED: &'static [u8] = &hex!("589c8718e8263a53a78932b6212a46e7fd52de3ad157b5bb277dba494cfd3471d4cc5f90685952917b33366efcce0512a1f8d70f974758266cb04fc424346d37b20f49cb2a081c94b1771fd8c172ae21785c61ea2c7e31947ce351e7b5ff07028c5329beb87b317ffcd981e440819d91136c988d6d9fbea4a87e55ed24a5993aa02f688ab1d3bd19056f94c8a44b8faddfa3c9c79c95ad44311a7bf00e5e862ec2c399f0d689dfb8c2dc0d7caba32afcf58cf0d85f78195a0b5ab732f565595492cfd982321d1f9be4b21fe6a0214306023d6a05d0d23f67ddc1c0400e5e0a5e92d17595131b7a095e740b884b8c9bb0226a39cfd027c769c4f4677c51f21b24da81fb2bd1356a9d0650f6a63fcc90d93bd74a954ba6f75f0e9fca47a6d21734bce7b28f06b76ef2c44d20a07026534e586eb8e1038874a93e44de362ce7bc0844bffc88e390c62519e281aa6fd53ff9ddd1d9ba303cf70004278ea2ae66ce05a2749d29eba56f3efe99e42902825c473dfc3c154c3762d2e76bd103f629d250b2d9d5c243a4cf8f3be21a84f153f44e2733a105cf780a20f03d84fe1ebbeb0e");
        const SYSTEM_HARDCODED: &'static [u8] = &hex!("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d7660f661d3be33ff1b8c54e4165a79cf2c044bcfa2fa56966d528bd50f544c3132");
    }

    #[test]
    fn test_system() { // May have a pitfall, each generated System param's HARDCODE should be the same
        let params = SystemParams::generate();
        let serialized = bincode::serialize(&params).expect("can serialize");
        println!("PARAMS = {:#x?}", serialized);
        assert!(serialized == SystemParams::SYSTEM_HARDCODED);
    }

    #[test]
    fn test_system_params_generate() {
        let params = SystemParams::generate();
        assert_eq!(params.p, BASEPOINT_ORDER);
        assert_eq!(params.g, RISTRETTO_BASEPOINT_POINT);
        assert_ne!(params.h, RISTRETTO_BASEPOINT_POINT);
    }

    #[test]
    fn round_trip_key_pair() {
        let key_pair = CredentialKeyPair::generate([0x42; RANDOMNESS_LEN]);
        let serialized = bincode::serialize(&key_pair).unwrap();
        let deserialized: CredentialKeyPair = bincode::deserialize(&serialized).unwrap();
        assert_eq!(&key_pair.public_key.X1, &deserialized.public_key.X1);
        assert_eq!(&key_pair.private_key.x0, &deserialized.private_key.x0);
    }
}