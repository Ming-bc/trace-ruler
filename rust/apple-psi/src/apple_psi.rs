extern crate cuckoofilter;
use std::{collections::hash_map::DefaultHasher, hash::RandomState, thread::sleep};
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint, Scalar};
use sha2::{Sha512, Sha256, Digest, digest::Update};
use serde::{Deserialize, Serialize};
use cuckoofilter::{bucket::{Bucket, Fingerprint, BUCKET_SIZE, EMPTY_FINGERPRINT_DATA, FINGERPRINT_SIZE}, util::get_fai_from_u8, CuckooFilter, ExportedCuckooFilter};
use poksho::{ShoApi, ShoHmacSha256, ShoSha256};
use zkcredential::{sho::ShoExt, RANDOMNESS_LEN};
use aes_gcm::aead::{Aead, KeyInit, Error};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand_core::{RngCore, OsRng};
use boring::{ec::{EcGroup, EcKey, EcKeyRef, EcPoint, EcPointRef}, ssl::select_next_proto};
use boring::nid::Nid;
use boring::bn::{BigNum, BigNumContext};
use boring::ecdsa::EcdsaSig;
use boring::pkey::{PKey, Private, Public};
use std::hash::{Hasher, Hash};
use std::fmt;
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;


pub const INPUT_LENGTH: usize = 32;
pub const CUCKOO_PARAM: f64 = 1.2;

#[derive(Debug)]
pub enum CertError {
    NotEmpty,
    PoKError,
}

impl fmt::Display for CertError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CertError::NotEmpty => write!(f, "It is empty in cuckoo table but not empty in K"),
            &CertError::PoKError => write!(f, "PoK failed!"),
        }
    }
}

pub fn get_hash_from_int(i: u32) -> [u8; INPUT_LENGTH]{
    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, &i.to_le_bytes()); // Transform u32 to byte array and calculate hash
    let hash = hasher.finalize();
    let output:[u8;INPUT_LENGTH] = hash.as_slice().try_into().expect("slice with incorrect length");
    output
}

pub fn sha256_to_ris(i:[u8;INPUT_LENGTH]) -> RistrettoPoint{
    let mut uniform_bytes = [0u8; 64];
    uniform_bytes[..32].copy_from_slice(&i);
    uniform_bytes[32..].copy_from_slice(&i);
    RistrettoPoint::from_uniform_bytes(&uniform_bytes)
}

pub fn aes_encrypt_from_ris(S: RistrettoPoint, m: &[u8]) -> Vec<u8>{
    let key_hash = Sha256::digest(S.compress().to_bytes());
    let key_bytes = &key_hash[..32];
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new(key);
    let ct = cipher.encrypt(&nonce, m.as_ref()).expect("encryption failure!");
    // let dct = cipher.decrypt(&nonce, ct.as_ref()).expect("decryption failure!");
    // println!("decrypt: {:?}", dct);

    // combine nouce together 
    let mut combined_message = Vec::new();
    combined_message.extend_from_slice(&nonce_bytes);
    combined_message.extend_from_slice(&ct);
    combined_message
}

pub fn aes_decrypt_from_ris(S: RistrettoPoint, c: Vec<u8>) -> Result<Vec<u8>, Error>{
    let received_nonce = Nonce::from_slice(&c[0..12]);
    let received_ciphertext = &c[12..];

    let key_hash = Sha256::digest(S.compress().to_bytes());
    let key_bytes = &key_hash[..32];
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    match cipher.decrypt(received_nonce, received_ciphertext) {
        Ok(decrypted_plaintext) => Ok(decrypted_plaintext),
        Err(e) => Err(e),
    }
}

pub fn sign_message(sk: &EcKeyRef<Private>, msg: &[u8]) -> EcdsaSig {
    let mut hasher = Sha256::new().chain(msg);
    // hasher.update(msg);
    let hashed_msg = hasher.finalize();

    EcdsaSig::sign(&hashed_msg, &sk).unwrap()
}

pub fn verify_message(pk: &EcKeyRef<Public>, msg: &[u8], sig: &EcdsaSig) -> bool {
    let mut hasher = Sha256::new().chain(msg);
    // hasher.update(msg);
    let hashed_msg = hasher.finalize();
    sig.verify(&hashed_msg, &pk).unwrap()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct APCEOuterEncryptResult{
    E1: APCEInnerEncryptResult,
    E2: APCEInnerEncryptResult,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct APCEInnerEncryptResult{
    Q: RistrettoPoint,
    ct: Vec<u8>,
}

impl APCEInnerEncryptResult {
    pub fn new(Q:RistrettoPoint, ct:Vec<u8>) -> Self{
        Self{
            Q,
            ct,
        }
    }
}

pub struct client{
    pk: RistrettoPoint,
    P: Vec<RistrettoPoint>,
}

impl client {
    pub fn new(pk: RistrettoPoint, P: Vec<RistrettoPoint>) -> Self{
        Self{
            pk,
            P,
        }
    }

    pub fn encryption(&self, m: &[u8], p: &[u8])->APCEOuterEncryptResult{
        let msg: [u8; INPUT_LENGTH] = m.try_into().unwrap();

        // compute m's indecies on cuckoo table
        let i1 = CuckooFilter::<DefaultHasher>::get_i1_from_u8(self.P.len(), &msg);
        let i2 = CuckooFilter::<DefaultHasher>::get_i2_from_u8(self.P.len(), &msg);

        let mut sho = ShoHmacSha256::new(b"JZ_Apple_PSI_Server_20240803");
        // sho.absorb_and_ratchet(&[0xff;32]);
        // let beta1 = sho.get_scalar();
        // let gamma1 = sho.get_scalar();
        // let beta2 = sho.get_scalar();
        // let gamma2 = sho.get_scalar();

        let beta1  = Scalar::random(&mut OsRng);
        let gamma1 = Scalar::random(&mut OsRng);
        let beta2  = Scalar::random(&mut OsRng);
        let gamma2 = Scalar::random(&mut OsRng);

        let hm = curve25519_dalek::RistrettoPoint::hash_from_bytes::<Sha512>(m);
        // Q = (H(m) * beta) + (g * gamma)
        let Q1 = (hm * beta1) + (RISTRETTO_BASEPOINT_POINT * gamma1);
        let Q2 = (hm * beta2) + (RISTRETTO_BASEPOINT_POINT * gamma2);
        // S = (P[i])
        let S1 = (self.P[i1] * beta1) + (self.pk * gamma1);
        let S2 = (self.P[i2] * beta2) + (self.pk * gamma2);

        // println!("Q1:{:?}", Q1.compress().as_bytes());
        // println!("Q2:{:?}", Q2.compress().as_bytes());
        // println!("S1:{:?}", S1.compress().as_bytes());
        // println!("S2:{:?}", S2.compress().as_bytes());
        let ct1 = aes_encrypt_from_ris(S1, p);
        let ct2 = aes_encrypt_from_ris(S2, p);
        // println!("encrypt: {:?}", m);
        // println!("ct: {:?}", ct1);

        let E1 = APCEInnerEncryptResult::new(Q1, ct1);
        let E2 = APCEInnerEncryptResult::new(Q2, ct2);


        APCEOuterEncryptResult{
            E1,
            E2,
        }

    }
}

#[derive(Clone)]
pub struct server<'a>{
    pub pk: RistrettoPoint,
    pub sk: Scalar,
    pub pk_ecdsa: EcKey<Public>,
    pub sk_ecdsa: EcKey<Private>,
    // pub 
    rb: Scalar,
    input: Vec<[u8;INPUT_LENGTH]>,
    pub T: cuckoofilter::CuckooFilter<DefaultHasher>,
    authenticated_message: &'a [u8],
}

impl<'a> server<'a> {

    pub fn generate_ecdsa_key(sk: &Scalar) -> EcKey<Private>{
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let priv_key_bn = BigNum::from_slice(&sk.to_bytes()).unwrap();
        // Compute public key
        let mut ctx = BigNumContext::new().unwrap();
        let mut public_key_point = EcPoint::new(&group).unwrap();
        public_key_point.mul_generator(&group, &priv_key_bn, &mut ctx).unwrap();
        // Generate EcKey object using private key
        let ec_key = EcKey::from_private_components(&group, &priv_key_bn, &public_key_point).unwrap();
        
        ec_key
    }

    pub fn sign_ecdsa(&self, msg: &[u8]) -> EcdsaSig{
        sign_message(&self.sk_ecdsa, msg)
    }

    pub fn verify_ecdsa(&self,msg: &[u8], sig: &EcdsaSig) -> bool{
        verify_message(&self.pk_ecdsa, msg, sig)
    }

    pub fn new(label: &'a [u8], randomness: &[u8;RANDOMNESS_LEN]) -> Self{
        let input = vec![];
        let T: CuckooFilter<DefaultHasher> = cuckoofilter::CuckooFilter::new();

        let mut sho = ShoHmacSha256::new(b"JZ_Apple_PSI_Server_20240803");
        sho.absorb_and_ratchet(randomness);
        let sk = sho.get_scalar();
        let rb = sho.get_scalar();
        let pk = RISTRETTO_BASEPOINT_POINT * sk;
        let sk_ecdsa = server::generate_ecdsa_key(&sk);
        let pk_point = sk_ecdsa.public_key();
        let pk_ecdsa = EcKey::from_public_key(sk_ecdsa.group(), pk_point).unwrap();
        Self{
            pk,
            sk,
            pk_ecdsa,
            sk_ecdsa,
            rb,
            input,
            T,
            authenticated_message: &label,
        }
    }

    pub fn decrypt(&self, ct: APCEOuterEncryptResult) -> Result<Vec<u8>, String> {
        let E1 = ct.E1;
        let E2 = ct.E2;
        let s1_prime = E1.Q * self.sk;
        let s2_prime = E2.Q * self.sk;
        // println!("Q1{:?}", E1.Q.compress().as_bytes());
        // println!("Q2{:?}", E2.Q.compress().as_bytes());
        // println!("s1_prime{:?}", s1_prime.compress().as_bytes());
        // println!("s2_prime{:?}", s2_prime.compress().as_bytes());
        // println!("pk{:?}", self.pk.compress().as_bytes());
        assert_eq!(self.pk, RISTRETTO_BASEPOINT_POINT*self.sk);
        let p1 = aes_decrypt_from_ris(s1_prime, E1.ct);
        let p2 = aes_decrypt_from_ris(s2_prime, E2.ct);

        match (p1, p2) {
            (Ok(p1), _) => Ok(p1),
            (_, Ok(p2)) => Ok(p2),
            (Err(e1), Err(e2)) => Err(format!("Decryption failed for both: {:?}, {:?}", e1, e2)),
        }
    }



    fn get_poksho_statement(&self) -> poksho::Statement {
        // See Chase-Perrin-Zaverucha section 3.2.
        let mut st = poksho::Statement::new();
        // K_i = H(T[i]) * sk
        st.add("K_i", &[("sk", "HT")]);
        // pk = g * sk
        st.add("pk", &[("sk", "g")]);

        st
    }

    fn prepare_scalar_args(
        &self,
        sk: Scalar,
    ) -> poksho::ScalarArgs {
        let mut scalar_args = poksho::ScalarArgs::new();
        scalar_args.add("sk", sk);
        scalar_args
    }

    fn prepare_point_args(
        &self,
        K_i: RistrettoPoint,
        HT: RistrettoPoint,
        pk: RistrettoPoint,
    ) -> poksho::PointArgs {

        let mut point_args = poksho::PointArgs::new();
        point_args.add("K_i", K_i);
        point_args.add("HT", HT);
        point_args.add("g", RISTRETTO_BASEPOINT_POINT);
        point_args.add("pk", pk);

        point_args
    }

    pub fn LGen(&mut self, input: Vec<[u8;INPUT_LENGTH]>, pk_ecdsa: EcKey<Public>, sk_ecdsa: EcKey<Private>, randomness: [u8; RANDOMNESS_LEN]) -> (Vec<RistrettoPoint>, Vec<EcdsaSig>){
        let mut sho = ShoHmacSha256::new(b"JZ_Apple_PSI_Server_20240803");
        sho.absorb_and_ratchet(&randomness);

        // handle inputs
        self.input = input.clone();
        let n = input.len() as f64 * CUCKOO_PARAM;  // size of the cuckoo table
        self.T = CuckooFilter::with_capacity(n as usize);
        self.insert_into_cuckoo();  // insert into cuckoo table
        let exported_cf = self.T.clone().export();
        let buckets = exported_cf.values.chunks(BUCKET_SIZE * FINGERPRINT_SIZE).map(Bucket::from).collect::<Vec<_>>();

        // K[i] = H(T[i])^sk or K[i] = random
        let mut sho = ShoHmacSha256::new(b"JZ_Apple_PSI_Server_20240803");
        sho.absorb_and_ratchet(&[0x12;32]);
        // in the paper, it is named T_bar
        let mut K: Vec<RistrettoPoint> = vec![];
        let mut Pi: Vec<Vec<u8>> = vec![];
        for(index, i) in buckets.iter().enumerate(){
            let mut ki: RistrettoPoint; // K[i]
            let proofi: Vec<u8>;
            let buc_item = i.buffer[0].data;
            if buc_item == EMPTY_FINGERPRINT_DATA{
                // sample random ri
                let ri = Scalar::random(&mut rand::thread_rng());
                ki = RISTRETTO_BASEPOINT_POINT * ri; // K[i] = g ^ ri if it is empty
                let mut scalar_args = poksho::ScalarArgs::new();
                scalar_args.add("ri", ri);
                let mut point_args = poksho::PointArgs::new();
                point_args.add("g", RISTRETTO_BASEPOINT_POINT);
                point_args.add("K_i", ki);
                let mut st = poksho::Statement::new();
                st.add("K_i", &[("ri", "g")]);
                proofi = st.prove(&scalar_args, &point_args, &self.authenticated_message, &randomness).unwrap();
                // verify that proof is correctly generated
                assert!(st.verify_proof(&proofi, &point_args, self.authenticated_message).is_ok());
            } else {
                let h2p = curve25519_dalek::RistrettoPoint::hash_from_bytes::<Sha512>(&buc_item);
                ki = h2p * self.sk;  // K[i] = H(T[i])^sk if it is not empty
                let scalar_args = self.prepare_scalar_args(self.sk);
                let point_args = self.prepare_point_args(ki, h2p, self.pk);
                proofi = self
                    .get_poksho_statement()
                    .prove(&scalar_args, &point_args, &self.authenticated_message, &randomness,)
                    .unwrap();
                // verify that proof is correctly generated
                assert!(self.get_poksho_statement().verify_proof(&proofi, &point_args, self.authenticated_message).is_ok());
            }
            K.push(ki);
            Pi.push(proofi);
        }

        let mut Sigma: Vec<EcdsaSig> = Vec::new();
        for(index, i) in buckets.iter().enumerate(){
            let buc_item = i.buffer[0].data;
            if buc_item == EMPTY_FINGERPRINT_DATA{
                let mut st = poksho::Statement::new();
                st.add("K_i", &[("ri", "g")]);
                let mut point_args = poksho::PointArgs::new();
                point_args.add("g", RISTRETTO_BASEPOINT_POINT);
                point_args.add("K_i", *K.get(index).unwrap());
                assert!(st.verify_proof(Pi.get(index).unwrap(), &point_args, self.authenticated_message).is_ok());

            } else {
                let h2p = curve25519_dalek::RistrettoPoint::hash_from_bytes::<Sha512>(&buc_item);
                let point_args = self.prepare_point_args(*K.get(index).unwrap(), h2p, self.pk);
                assert!(self.get_poksho_statement().verify_proof(Pi.get(index).unwrap(), &point_args, self.authenticated_message).is_ok());
            }
            let k_i_bytes = K.get(index).unwrap().compress().to_bytes();

            let sigma_i = sign_message(&sk_ecdsa, &k_i_bytes);
            let res = verify_message(&pk_ecdsa, &k_i_bytes, &sigma_i);
            Sigma.push(sigma_i);
        }
        (K, Sigma)
    }

    // LGen
    pub fn setup(&mut self, input: Vec<[u8;INPUT_LENGTH]>, randomness: [u8; RANDOMNESS_LEN]) -> Vec<RistrettoPoint>{
        let mut sho = ShoHmacSha256::new(b"JZ_Apple_PSI_Server_20240803");
        sho.absorb_and_ratchet(&randomness);

        // handle inputs
        self.input = input.clone();
        let n = input.len() as f64 * CUCKOO_PARAM;  // size of the cuckoo table
        self.T = CuckooFilter::with_capacity(n as usize);
        self.insert_into_cuckoo();  // insert into cuckoo table

        let exported_cf = self.T.export();
        let buckets = exported_cf.values.chunks(BUCKET_SIZE * FINGERPRINT_SIZE).map(Bucket::from).collect::<Vec<_>>();

        // K[i] = H(T[i])^sk or K[i] = random
        let mut sho = ShoHmacSha256::new(b"JZ_Apple_PSI_Server_20240803");
        sho.absorb_and_ratchet(&[0x12;32]);
        let mut K: Vec<RistrettoPoint> = vec![];
        let mut Pi: Vec<Vec<u8>> = vec![];
        for(index, i) in buckets.iter().enumerate(){
            let mut ki: RistrettoPoint; // K[i]
            let buc_item = i.buffer[0].data;
            // println!("buc item in {} is {:?}", index, buc_item);
            if buc_item == EMPTY_FINGERPRINT_DATA{
                let ri = Scalar::random(&mut OsRng);
                let hind = get_hash_from_int(index as u32);
                let h2p = sha256_to_ris(hind);
                ki = h2p * ri; // K[i] = H(i) ^ ri if it is empt
            } else {
                let h2p = curve25519_dalek::RistrettoPoint::hash_from_bytes::<Sha512>(&buc_item);
                ki = h2p * self.sk;  // K[i] = H(T[i])^sk if it is not empty
            }
            K.push(ki);
        }
        K
    }

    pub fn setup_multi_threaded(&mut self, input: Vec<[u8; INPUT_LENGTH]>, randomness: [u8; RANDOMNESS_LEN]) -> Vec<RistrettoPoint>{
        let mut sho = ShoHmacSha256::new(b"JZ_Apple_PSI_Server_20240803");
        sho.absorb_and_ratchet(&randomness);
    
        // handle inputs
        self.input = input.clone();
        let n = input.len() as f64 * CUCKOO_PARAM;  // size of the cuckoo table
        self.T = CuckooFilter::with_capacity(n as usize);
        self.insert_into_cuckoo();  // insert into cuckoo table
    
        let exported_cf = self.T.export();
        let buckets = exported_cf.values.chunks(BUCKET_SIZE * FINGERPRINT_SIZE).map(Bucket::from).collect::<Vec<_>>();
    
        // K[i] = H(T[i])^sk or K[i] = random
        let mut sho = ShoHmacSha256::new(b"JZ_Apple_PSI_Server_20240803");
        sho.absorb_and_ratchet(&[0x12;32]);
    
        let results: Vec<RistrettoPoint> = buckets
            .par_iter()
            .enumerate()
            .map(|(index, i)| {
                let ki: RistrettoPoint;
                let buc_item = i.buffer[0].data;
    
                if buc_item == EMPTY_FINGERPRINT_DATA {
                    let hind = get_hash_from_int(index as u32);
                    let h2p = sha256_to_ris(hind);
                    ki = h2p * self.rb; // K[i] = H(i) ^ rb if it is empty
                } else {
                    let h2p = curve25519_dalek::RistrettoPoint::hash_from_bytes::<Sha512>(&buc_item);
                    ki = h2p * self.sk;  // K[i] = H(T[i])^sk if it is not empty
                }
    
                ki
            })
            .collect();
    
        let K: Vec<RistrettoPoint> = results;
        
        K
    }

    pub fn LCert(&mut self, exported_cf: ExportedCuckooFilter, K: &Vec<RistrettoPoint>, Pi: Vec<Vec<u8>>, randomness: [u8; RANDOMNESS_LEN])-> Result<Vec<EcdsaSig>, CertError>{
        let buckets = exported_cf.values.chunks(BUCKET_SIZE * FINGERPRINT_SIZE).map(Bucket::from).collect::<Vec<_>>();
        let mut Sigma: Vec<EcdsaSig> = Vec::new();
        for(index, i) in buckets.iter().enumerate(){
            let buc_item = i.buffer[0].data;
            if buc_item == EMPTY_FINGERPRINT_DATA{
                let mut st = poksho::Statement::new();
                st.add("K_i", &[("ri", "g")]);
                let mut point_args = poksho::PointArgs::new();
                point_args.add("g", RISTRETTO_BASEPOINT_POINT);
                point_args.add("K_i", *K.get(index).unwrap());
                assert!(st.verify_proof(Pi.get(index).unwrap(), &point_args, self.authenticated_message).is_ok());

            } else {
                let h2p = curve25519_dalek::RistrettoPoint::hash_from_bytes::<Sha512>(&buc_item);
                let point_args = self.prepare_point_args(*K.get(index).unwrap(), h2p, self.pk);
                assert!(self.get_poksho_statement().verify_proof(Pi.get(index).unwrap(), &point_args, self.authenticated_message).is_ok());
            }
            let k_i_bytes = K.get(index).unwrap().compress().to_bytes();

            let sigma_i = sign_message(&self.sk_ecdsa, &k_i_bytes);
            let res = verify_message(&self.pk_ecdsa, &k_i_bytes, &sigma_i);
            Sigma.push(sigma_i);
        }

        Ok(Sigma)
    }

    // lcert
    pub fn cert(&mut self, input: Vec<[u8;INPUT_LENGTH]>, randomness: [u8; RANDOMNESS_LEN], K: Vec<RistrettoPoint>, Pi: Vec<Vec<u8>>) -> Result<Vec<EcdsaSig>, CertError>{
        let mut sho = ShoHmacSha256::new(b"JZ_Apple_PSI_Server_20240803");
        sho.absorb_and_ratchet(&randomness);

        // handle inputs
        self.input = input.clone();
        let n = input.len() as f64 * CUCKOO_PARAM;  // size of the cuckoo table
        for i in input.iter(){
            self.T.delete(&i);
        }
        self.T.clear();
        self.T = CuckooFilter::with_capacity(n as usize);
        self.insert_into_cuckoo();  // insert into cuckoo table

        let exported_cf = self.T.export();
        let buckets = exported_cf.values.chunks(BUCKET_SIZE * FINGERPRINT_SIZE).map(Bucket::from).collect::<Vec<_>>();
        let mut Sigma: Vec<EcdsaSig> = vec![];
        
        for (index, i) in buckets.iter().enumerate(){
            let buc_item = i.buffer[0].data;
            // println!("buc item in {} is {:?}", index, buc_item);
            if buc_item == EMPTY_FINGERPRINT_DATA{
                let hind = get_hash_from_int(index as u32);
                let h2p = sha256_to_ris(hind);
                let ki = h2p * self.rb;
                if K[index] != ki{
                    return Err(CertError::NotEmpty);
                }
                let fake_ki = h2p * self.sk;
                let point_args = self.prepare_point_args(fake_ki, h2p, self.pk);

            } else {
                //println!("buc item in {} is {:?}", index, buc_item);
                let h2p = curve25519_dalek::RistrettoPoint::hash_from_bytes::<Sha512>(&buc_item);
                let point_args = self.prepare_point_args(K[index], h2p, self.pk);
                let proof_res = self.get_poksho_statement().verify_proof(&Pi[index], &point_args, self.authenticated_message).is_ok();
                // println!("PoK for {} is {:?}", index, Pi[index]);
                // println!("K in {} is {:?}", index, K[index].compress().as_bytes());
                // println!("h2p in {} is {:?}", index, h2p.compress().as_bytes());
                // println!("pk in {} is {:?}", index, self.pk.compress().as_bytes());
                if !proof_res{
                    return Err(CertError::PoKError);
                }
            }
            let k_i_bytes = K[index].compress().to_bytes();

            let sigma_i = sign_message(&self.sk_ecdsa, &k_i_bytes);
            let res = verify_message(&self.pk_ecdsa, &k_i_bytes, &sigma_i);

            // println!("PK in {} is {:?}", index, self.pk_ecdsa.public_key_to_der().unwrap());
            // println!("Message in {} is {:?}", index, k_i_bytes);
            // println!("Signature in {} is {:?}", index, sigma_i.as_ref().to_der().unwrap());
            
            assert!(res);
            Sigma.push(sigma_i);
        }

        Ok(Sigma)
    }

    pub fn cert_multi_threaded(&mut self, input: Vec<[u8; INPUT_LENGTH]>, randomness: [u8; RANDOMNESS_LEN], K: Vec<RistrettoPoint>, Pi: Vec<Vec<u8>>) -> Result<Vec<EcdsaSig>, CertError> {
        let mut sho = ShoHmacSha256::new(b"JZ_Apple_PSI_Server_20240803");
        sho.absorb_and_ratchet(&randomness);
    
        // handle inputs
        self.input = input.clone();
        let n = input.len() as f64 * CUCKOO_PARAM;  // size of the cuckoo table
        for i in input.iter() {
            self.T.delete(&i);
        }
        self.T.clear();
        self.T = CuckooFilter::with_capacity(n as usize);
        self.insert_into_cuckoo();  // insert into cuckoo table
    
        let exported_cf = self.T.export();
        let buckets = exported_cf.values.chunks(BUCKET_SIZE * FINGERPRINT_SIZE).map(Bucket::from).collect::<Vec<_>>();
        
        let results: Result<Vec<EcdsaSig>, CertError> = buckets
            .par_iter()
            .enumerate()
            .map(|(index, i)| -> Result<EcdsaSig, CertError> {
                let buc_item = i.buffer[0].data;
    
                if buc_item == EMPTY_FINGERPRINT_DATA {
                    let hind = get_hash_from_int(index as u32);
                    let h2p = sha256_to_ris(hind);
                    let ki = h2p * self.rb;
                    if K[index] != ki {
                        return Err(CertError::NotEmpty);
                    }
                    let fake_ki = h2p * self.sk;
                    let point_args = self.prepare_point_args(fake_ki, h2p, self.pk);
    
                } else {
                    let h2p = RistrettoPoint::hash_from_bytes::<Sha512>(&buc_item);
                    let point_args = self.prepare_point_args(K[index], h2p, self.pk);
                    let proof_res = self.get_poksho_statement().verify_proof(&Pi[index], &point_args, self.authenticated_message).is_ok();
    
                    if !proof_res {
                        return Err(CertError::PoKError);
                    }
                }
                let k_i_bytes = K[index].compress().to_bytes();
    
                let sigma_i = sign_message(&self.sk_ecdsa, &k_i_bytes);
                let res = verify_message(&self.pk_ecdsa, &k_i_bytes, &sigma_i);
    
                assert!(res);
                Ok(sigma_i)
            })
            .collect();
    
        results
    }



    pub fn hash_input(&mut self){
        let mut hashed_input: Vec<[u8;INPUT_LENGTH]> = vec![];
        for i in self.input.iter() {
            let hash = Sha256::digest(i);
            hashed_input.push(hash.as_slice().try_into().expect("slice with incorrect length"));
        }
    }

    pub fn print_input(&self){
        for i in self.input.iter() {
            println!("{:?}", i);
        }
    }

    pub fn insert_into_cuckoo(&mut self) {
        for i in self.input.iter(){
            self.T.test_and_add_u8(&i);
        }
        // for i in self.input.iter(){
        //     if !self.T.contains_u8(&i){
        //         println!("insertion failed for {:?}", i);
        //     }
        // }
    }


}

#[cfg(test)]
mod test{
    use std::ops::Index;

    use rand::RngCore;

    use super::*;
    // #[test]
    // fn test_aes() {


    // }

    #[test]
    fn test_setup_and_enc_dec() {
        let mut input: Vec<[u8;INPUT_LENGTH]> = vec![];
        let mut i:u32 = 0;
        let n :u32= 100;
        while i < n{
            let mut hasher = Sha256::new().chain(&i.to_le_bytes());
            // hasher.update(&i.to_le_bytes()); // Transform u32 to byte array and calculate hash
            let hash = hasher.finalize();
            input.push(hash.as_slice().try_into().expect("slice with incorrect length"));
            i += 1;
        }
        let randomness:[u8;RANDOMNESS_LEN] = [0x11;RANDOMNESS_LEN];
        let mut s = server::new(b"my server", &randomness);

        let K = s.setup(input, randomness);
        let ct = s.T.export();
        let buckets = ct.values.chunks(BUCKET_SIZE * FINGERPRINT_SIZE).map(Bucket::from).collect::<Vec<_>>();
        for (index, i) in buckets.iter().enumerate(){
            let item = i.buffer[0].data;
            // println!("PK in {} is {:?}", index, s.pk_ecdsa.public_key().public_key_to_der().unwrap());
            // println!("Message in {} is {:?}", index, k_i_bytes);
            // println!("Signature in {} is {:?}", index, s.sign_ecdsa(&k_i_bytes).as_ref().to_der().unwrap());
            // println!("buc item in {} is {:?}", index, item);
        }

        // test for lookup by client
        let mut i:u32 = 5;
        
        let mut hasher = Sha256::new().chain(&i.to_le_bytes());
        // hasher.update(&i.to_le_bytes()); // Transform u32 to byte array and calculate hash
        let hash = hasher.finalize();
        let test_input:[u8;INPUT_LENGTH] = hash.as_slice().try_into().expect("slice with incorrect length");
        // println!("{:?}", test_input);
        let i1 = CuckooFilter::<DefaultHasher>::get_i1_from_u8(buckets.len(), &test_input);
        let i2 = CuckooFilter::<DefaultHasher>::get_i2_from_u8(buckets.len(), &test_input);
        // println!("buckets len: {}", buckets.len());
        // println!("i1: {}, i2: {}", i1, i2);
        let item1 = &buckets[i1].buffer[0].data;
        let item2 = &buckets[i2].buffer[0].data;
        let match1 = (item1 == &test_input);
        let match2 = (item2 == &test_input);
        assert!(match1|match2);
        assert_eq!(buckets.len(), K.len());

        // should not be error
        let c = client::new(s.pk, K.clone());
        let p = [0u8;544];
        let ct = c.encryption(&test_input, &p);
        let pt = s.decrypt(ct).expect("decryption should succeed");
        assert_eq!(pt, p.to_vec());

        // should be error
        let c2 = client::new(RISTRETTO_BASEPOINT_POINT, K);
        let ct = c2.encryption(&test_input, &p);
        let pt = s.decrypt(ct);
        assert!(pt.is_err());
    }



    #[test]
    fn test_server() {
        let input: Vec<[u8;INPUT_LENGTH]> = vec![[0x1;INPUT_LENGTH], [0x2;INPUT_LENGTH], [0x3;INPUT_LENGTH], [0x4;INPUT_LENGTH]];
        let randomness:[u8;RANDOMNESS_LEN] = [0x11;RANDOMNESS_LEN];
        let mut s = server::new(b"my server", &randomness);
        let randomness = [0x11; RANDOMNESS_LEN];
        s.setup(input, randomness);
        // println!("{}", s.T.len());
        // Test that the input after hashing is included in the cf
        let cf = s.T.export();
        let buckets = cf.values.chunks(BUCKET_SIZE * FINGERPRINT_SIZE).map(Bucket::from).collect::<Vec<_>>();
        // println!("{:?}", s.T.values());
        let mut n = 0;
        for i in buckets.iter(){
            let fp = &i.buffer[0].data;
            //println!("{:?}", fp);
            for j in s.input.iter(){
                if fp == j {
                    //println!("{:?}", fp);
                    n += 1;
                }
            }
        }
        // Test that the fingerprint is the input value
        assert_eq!(s.input.len(), n);
    }

    #[test]
    fn test() {
        // prepare input
        let words: Vec<[u8;INPUT_LENGTH]> = vec![[0x1;INPUT_LENGTH], [0x2;INPUT_LENGTH], [0x3;INPUT_LENGTH], [0x4;INPUT_LENGTH]];
        let mut hashed_words: Vec<[u8;INPUT_LENGTH]> = vec![];
        for i in words.iter(){
            let hash = Sha256::digest(i);
            hashed_words.push(hash.as_slice().try_into().expect("slice with incorrect length"));
        }
        let mut cf = cuckoofilter::CuckooFilter::new();

        let mut insertions = 0;
        for s in &hashed_words {
            if cf.test_and_add(s).unwrap() {
                insertions += 1;
            }
        }

        assert_eq!(insertions, hashed_words.len());
        assert_eq!(cf.len(), hashed_words.len());

        // Re-add the first element.
        cf.add(&hashed_words[0]);

        assert_eq!(cf.len(), hashed_words.len() + 1);

        for s in &hashed_words {
            cf.delete(s);
        }

        assert_eq!(cf.len(), 1);
        assert!(!cf.is_empty());

        cf.delete(&hashed_words[0]);

        assert_eq!(cf.len(), 0);
        assert!(cf.is_empty());
    }

    #[test]
    fn test_cuckoo(){ // Ensure two cuckoo tables generated with the same input are the same
        let mut input: Vec<[u8;INPUT_LENGTH]> = vec![];
        let mut i:u32 = 0;
        let n :u32= 1000;
        while i < n{
            let mut hasher = Sha256::new().chain(&i.to_le_bytes());
            // hasher.update(&i.to_le_bytes()); // Transform u32 to byte array and calculate hash
            let hash = hasher.finalize();
            input.push(hash.as_slice().try_into().expect("slice with incorrect length"));
            i += 1;
        }
        let randomness:[u8;RANDOMNESS_LEN] = [0x11;RANDOMNESS_LEN];
        let mut s = server::new(b"my server", &randomness);
        
        let mut T1 = cuckoofilter::CuckooFilter::new();
        let mut T2 = cuckoofilter::CuckooFilter::new();

        T1 = cuckoofilter::CuckooFilter::with_capacity(input.len());
        T2 = cuckoofilter::CuckooFilter::with_capacity(input.len());

        for i in input{
            T1.test_and_add_u8(&i);
            T2.test_and_add_u8(&i);
        }

        let ex1 = T1.export();
        let ex2 = T2.export();

        let buc1 = ex1.values.chunks(BUCKET_SIZE * FINGERPRINT_SIZE).map(Bucket::from).collect::<Vec<_>>();
        let buc2 = ex2.values.chunks(BUCKET_SIZE * FINGERPRINT_SIZE).map(Bucket::from).collect::<Vec<_>>();

        for (index, i) in buc1.iter().enumerate(){
            let item1 = i.buffer[0].data.clone();
            let item2 = buc2[index].buffer[0].data.clone();
            assert_eq!(item1, item2);
            // println!("index {}: {:?}---{:?}", index, item1, item2);
        }

        


    }
        

    #[test]
    fn test_sign(){
        let mut sho = ShoHmacSha256::new(b"JZ_Apple_PSI_Server_20240803");
        let randomness = [0x12;RANDOMNESS_LEN];
        sho.absorb_and_ratchet(&randomness);
        let mut s = server::new(b"my server", &randomness);
        let sk = s.sk_ecdsa;
        let pk = s.pk_ecdsa;

        let m = b"hahhaha";

        // Test whether the key is generated correctly
        let sig = sign_message(sk.as_ref(), s.pk.compress().as_bytes());
        println!("{}", sig.as_ref().to_der().unwrap().len());
        let res = verify_message(pk.as_ref(), m, &sig);
        // assert!(res);

        let mut input: Vec<[u8;INPUT_LENGTH]> = vec![];
        let mut i:u32 = 0;
        let n :u32= 10;
        while i < n{
            let mut hasher = Sha256::new().chain(&i.to_le_bytes());
            // hasher.update(&i.to_le_bytes()); // Transform u32 to byte array and calculate hash
            let hash = hasher.finalize();
            input.push(hash.as_slice().try_into().expect("slice with incorrect length"));
            i += 1;
        }
        let randomness:[u8;RANDOMNESS_LEN] = [0x11;RANDOMNESS_LEN];

        let mut s = server::new(b"my server2", &randomness);
        let sk = s.clone().sk_ecdsa;
        let pk = s.clone().pk_ecdsa;

        let K = s.setup(input.clone(), randomness);
        
    }
}