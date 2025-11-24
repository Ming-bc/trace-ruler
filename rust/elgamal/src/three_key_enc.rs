use std::fs::create_dir;

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
use rand_core::OsRng;
use crate::encryption::cipher_text;

pub fn MPEnc(pk1: RistrettoPoint, pk2: RistrettoPoint, pk3: RistrettoPoint, m: RistrettoPoint) -> cipher_text{
    let r = Scalar::random(&mut OsRng);
    let E1 = RISTRETTO_BASEPOINT_POINT * r;
    let E2 = r * pk1 + r * pk2 + r * pk3 + m;
    cipher_text{
        E1,
        E2,
    }
}

pub fn MPEnc_with_r(pk1: RistrettoPoint, pk2: RistrettoPoint, pk3: RistrettoPoint, m: RistrettoPoint, r: Scalar) -> cipher_text{
    let E1 = RISTRETTO_BASEPOINT_POINT * r;
    let E2 = r * pk1 + r * pk2 + r * pk3 + m;
    cipher_text{
        E1,
        E2,
    }
}

pub fn MPDec1(ct: cipher_text, sk: Scalar) -> cipher_text{
    let E2 = ct.E2 - ct.E1 * sk;
    let E1 = ct.E1;
    cipher_text{
        E1,
        E2
    }
}

pub fn MPDec2(ct: cipher_text, sk: Scalar) -> RistrettoPoint{
    let E2 = ct.E2 - ct.E1 * sk;
    E2
}

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
pub struct three_enc_key_pair{
    pub sk: three_enc_pri_key,
    pub pk: three_enc_pub_key,
}

impl three_enc_key_pair {
    // generate key for elgamal
    pub fn genarate(randomness: [u8; RANDOMNESS_LEN]) -> Self{
        let mut sho = ShoHmacSha256::new(b"Signal_ZKCredential_CredentialPrivateKey_generate_20230410");
        sho.absorb_and_ratchet(&randomness);

        let system = *SYSTEM_PARAMS;
        let sk1 = sho.get_scalar();
        let sk2 = sho.get_scalar();
        let sk3 = sho.get_scalar();

        let system = *SYSTEM_PARAMS;
        let pk1 = system.g * sk1;
        let pk2 = system.g * sk2;
        let pk3 = system.g * sk3;
        let pk = three_enc_pub_key{pk1, pk2, pk3};
        let sk = three_enc_pri_key{sk1, sk2, sk3};
        Self{
            sk,
            pk,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialDefault, Debug)]pub struct three_enc_pub_key{
    pub pk1: RistrettoPoint,
    pub pk2: RistrettoPoint,
    pub pk3: RistrettoPoint,
}


#[derive(Serialize, Deserialize, Clone, PartialDefault, Debug)]
pub struct three_enc_pri_key{
    pub sk1: Scalar,
    pub sk2: Scalar,
    pub sk3: Scalar,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ThreeKeyEncryption{
    pk: three_enc_pub_key,
}

impl ThreeKeyEncryption{
    pub fn new(pk: three_enc_pub_key) -> Self{
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
        let E2 = (self.pk.pk1 * r + self.pk.pk2 * r + self.pk.pk3 * r) + message;
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
        let E2 = (self.pk.pk1 * r + self.pk.pk2 * r + self.pk.pk3 * r) + message;
        cipher_text{
            E1,
            E2,
        }
    }
}


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ThreeKeyDecryption{
    sk: Scalar,
}

impl ThreeKeyDecryption{
    pub fn new(sk: Scalar) -> Self{
        ThreeKeyDecryption{
            sk,
        }
    }

    pub fn dec1(self, ct: &cipher_text) -> cipher_text{
        let E1 = ct.E1;
        // E2 = E2 / (E1 * sk2)
        let E2 = (ct.E2) - (ct.E1 * self.sk);
        cipher_text{
            E1,
            E2,
        }
    }

    pub fn dec2(self, ct: &cipher_text) -> RistrettoPoint{
        let m = ct.E2 - (ct.E1 * self.sk);
        m
    }
}


#[cfg(test)]
mod tests {
    use std::{f128::consts::E, sync::OnceLock};

    use super::*;

    #[test]
    fn test_MPEnc(){ 
        let mut sho = ShoHmacSha256::new(b"JZ_ElGamal_20240731");
        let randomness = [0x42; RANDOMNESS_LEN];
        sho.absorb_and_ratchet(&randomness);
        let m = sho.get_point();
        let sk1 = sho.get_scalar();
        let sk2 = sho.get_scalar();
        let sk3 = sho.get_scalar();
        let pk1 = RISTRETTO_BASEPOINT_POINT * sk1;
        let pk2 = RISTRETTO_BASEPOINT_POINT * sk2;
        let pk3 = RISTRETTO_BASEPOINT_POINT * sk3;
        let pk = three_enc_pub_key{pk1, pk2, pk3};
        let sk = three_enc_pri_key{sk1, sk2, sk3};

        let dec1 = ThreeKeyDecryption::new(sk1);
        let dec2 = ThreeKeyDecryption::new(sk2);
        let dec3 = ThreeKeyDecryption::new(sk3);
        let enc = ThreeKeyEncryption::new(pk);
        let ct = enc.clone().encrypt(randomness, m);
        let ct1 = dec1.clone().dec1(&ct);
        let ct2 = dec2.clone().dec1(&ct1);
        let m2 = dec3.clone().dec2(&ct2);
        assert_eq!(m, m2, "This two point should be equal!!!");
        
        let m3 = sho.get_point();
        let ct = enc.clone().encrypt(randomness, m3);
        let ct1 = dec1.clone().dec1(&ct);
        let ct2 = dec2.clone().dec1(&ct1);
        let m4 = dec3.clone().dec2(&ct2);
        assert_eq!(m3, m4, "This two points should be equal!!!");
        assert_ne!(m2, m4, "This two points should not be equal!!!");

        let ct = MPEnc(pk1, pk2, pk3, m);
        let ct1 = MPDec1(ct, sk1);
        let ct2 = MPDec1(ct1, sk2);
        let m2 = MPDec2(ct2, sk3);
        assert_eq!(m, m2, "This two points should be equal!!!");

    }

}