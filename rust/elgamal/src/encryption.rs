use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::constants::BASEPOINT_ORDER;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use poksho::{ShoApi, ShoHmacSha256, ShoSha256};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use lazy_static::lazy_static;
use crate::RANDOMNESS_LEN;
use zkcredential::sho::ShoExt;
use partial_default::PartialDefault;

/// Parameters shared by encryption and decryption
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct SystemParams {
    pub p: Scalar, //group order
    pub g: RistrettoPoint, // generator g
}

impl SystemParams {
    /// An arbitrary set of independent points generated through a constant sequence of hash
    /// operations.
    pub fn generate() -> Self {
        let mut sho = ShoSha256::new(b"Signal_ZKCredential_ConstantSystemParams_generate_20230410");
        let p = BASEPOINT_ORDER;
        let g = RISTRETTO_BASEPOINT_POINT;

        SystemParams {
            p,
            g,
        }
    }

    pub fn get_hardcoded() -> SystemParams {
        *SYSTEM_PARAMS
    }
}

lazy_static! {
    static ref SYSTEM_PARAMS: SystemParams = SystemParams::generate();
}

#[derive(Serialize, Deserialize, Clone, PartialDefault, Debug)]
pub struct cipher_text{
    pub E1: RistrettoPoint,
    pub E2: RistrettoPoint,
}

#[derive(Serialize, Deserialize, Clone, PartialDefault, Debug)]
pub struct elgamal_key_pair{
    pub sk: elgamal_private_key,
    pub pk: elgamal_public_key,
}

impl elgamal_key_pair {
    // generate key for elgamal
    pub fn genarate(randomness: [u8; RANDOMNESS_LEN]) -> Self{
        let mut sho = ShoHmacSha256::new(b"Signal_ZKCredential_CredentialPrivateKey_generate_20230410");
        sho.absorb_and_ratchet(&randomness);

        let system = *SYSTEM_PARAMS;
        let sk1 = sho.get_scalar();
        let sk2 = sho.get_scalar();

        let system = *SYSTEM_PARAMS;
        let pk1 = system.g * sk1;
        let pk2 = system.g * sk2;
        let pk = elgamal_public_key{pk1, pk2};
        let sk = elgamal_private_key{sk1, sk2};
        Self{
            sk,
            pk,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialDefault, Debug)]pub struct elgamal_public_key{
    pub pk1: RistrettoPoint,
    pub pk2: RistrettoPoint,
}


#[derive(Serialize, Deserialize, Clone, PartialDefault, Debug)]
pub struct elgamal_private_key{
    pub sk1: Scalar,
    pub sk2: Scalar,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ElGamalEncryption{
    pk: elgamal_public_key,
}

impl ElGamalEncryption{
    pub fn new(pk: elgamal_public_key) -> Self{
        Self{
            pk,
        }
    }

    pub fn encrypt(self, randomness: [u8; RANDOMNESS_LEN], message: RistrettoPoint) -> cipher_text{
        let mut sho = ShoHmacSha256::new(b"JZ_ElGamal_20240731");
        sho.absorb_and_ratchet(&randomness);
        let r = sho.get_scalar();
        let system = *SYSTEM_PARAMS;
        // E1 = g ^ r
        let E1 = system.g * r;
        // E2 = pk1 ^ r + pk2 ^ r + m
        let E2 = (self.pk.pk1 * r + self.pk.pk2 * r) + message;
        cipher_text{
            E1,
            E2,
        }
    }

    pub fn encrypt_with_r(self, r: Scalar, message: RistrettoPoint) -> cipher_text{
        let system = *SYSTEM_PARAMS;
        // E1 = g ^ r
        let E1 = system.g * r;
        // E2 = pk1 ^ r + pk2 ^ r + m
        let E2 = (self.pk.pk1 * r + self.pk.pk2 * r) + message;
        cipher_text{
            E1,
            E2,
        }
    }
}


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ElGamalDecryption{
    sk: Scalar,
}

impl ElGamalDecryption{
    pub fn new(sk: Scalar) -> Self{
        ElGamalDecryption{
            sk,
        }
    }

    pub fn process(self, ct: cipher_text) -> cipher_text{
        let E1 = ct.E1;
        // E2 = E2 / (E1 * sk2)
        let E2 = (ct.E2) - (ct.E1 * self.sk);
        cipher_text{
            E1,
            E2,
        }
    }
    pub fn decrypt(self, ct:&cipher_text) -> RistrettoPoint{
        // m = E2 / (E1 * sk1)
        let m = ct.E2 - (ct.E1 * self.sk);
        m
    }
}


#[cfg(test)]
mod tests {
    use std::{f128::consts::E, sync::OnceLock};

    use super::*;

    #[test]
    fn test_elgamal(){ 
        let mut sho = ShoHmacSha256::new(b"JZ_ElGamal_20240731");
        let randomness = [0x42; RANDOMNESS_LEN];
        sho.absorb_and_ratchet(&randomness);
        let m = sho.get_point();
        let sk1 = sho.get_scalar();
        let sk2 = sho.get_scalar();
        let pk1 = RISTRETTO_BASEPOINT_POINT * sk1;
        let pk2 = RISTRETTO_BASEPOINT_POINT * sk2;
        let pk = elgamal_public_key{pk1, pk2};
        let sk = elgamal_private_key{sk1, sk2};

        let dec1 = ElGamalDecryption::new(sk1);
        let dec2 = ElGamalDecryption::new(sk2);
        let enc = ElGamalEncryption::new(pk);
        let ct = enc.clone().encrypt(randomness, m);
        let processed_ct = dec1.clone().process(ct);
        let m2 = dec2.clone().decrypt(&processed_ct);
        assert_eq!(m, m2, "This two point should be equal!!!");
        
        let m3 = sho.get_point();
        let ct = enc.clone().encrypt(randomness, m3);
        let processed_ct = dec1.clone().process(ct);
        let m4 = dec2.decrypt(&processed_ct);
        assert_eq!(m3, m4, "This two points should be equal!!!");
        assert_ne!(m2, m4, "This two points should not be equal!!!");

    }

}