use std::sync::Arc;

// use apple_psi::{apple_psi::{self, aes_encrypt_from_ris, client, server, INPUT_LENGTH}, RANDOMNESS_LEN };
use apple_psi::{apple_psi::{aes_encrypt_from_ris, aes_decrypt_from_ris, client, server, APCEOuterEncryptResult, INPUT_LENGTH}, RANDOMNESS_LEN};
use boring::{ecdsa::EcdsaSig, sha};
use curve25519_dalek::{RistrettoPoint, Scalar};
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use sha2::{digest::Update, Digest, Sha256, Sha512};
use zkcredential::{credentials::{Credential, CredentialKeyPair, SystemParams}, issuance::{IssuanceProof}, presentation::PresentationProof};
use elgamal::{encryption::{elgamal_public_key, ElGamalDecryption, ElGamalEncryption, cipher_text}};
use elgamal::three_key_enc::{MPEnc, MPDec1, MPDec2, MPEnc_with_r};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use poksho::{ShoApi, ShoHmacSha256, ShoSha256};
use zkcredential::{sho::ShoExt};
use shamir::shamir::{Aggregation, TAR_Aggregate, TAR_share, SecretShare, Share};
// use serde::{Serialize, Deserialize};
use serde_json;
use boring::{ec::{EcGroup, EcKey, EcKeyRef, EcPoint, EcPointRef}, ssl::select_next_proto};
use boring::pkey::{PKey, Private, Public};
use rand_core::{impls::next_u64_via_u32, OsRng};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};
use hpke::{Kem as KemTrait};
use pke::Kem;


pub mod Moderator;
pub mod Regulator;
pub mod User;
pub mod Platform;
pub mod aes;
pub mod bench;
pub mod pke;

pub const THRESHOLD: usize = 3;

pub enum InspectResult {
    CtMSlice(Vec<u8>),
    MsgTmd([u8; 32], tmd_prime),
}

// create a new type to wrap Arc<EcdsaSig>
#[derive(Clone)]
pub struct SerializableEcdsaSig(Arc<EcdsaSig>);

impl Serialize for SerializableEcdsaSig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let der = self.0.to_der().map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&hex::encode(der)) // 使用hex编码为字符串
    }
}

impl<'de> Deserialize<'de> for SerializableEcdsaSig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str: String = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        let sig = EcdsaSig::from_der(&bytes).map_err(serde::de::Error::custom)?;
        Ok(SerializableEcdsaSig(Arc::new(sig)))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct token{
    u: RistrettoPoint,
    C_m: RistrettoPoint,
    C_U_Prime: RistrettoPoint,
    signature: SerializableEcdsaSig,
}

impl token{
    pub fn get_omega_bytes(&self) -> Vec<u8>{
        let u_bytes: [u8; 32] = self.u.compress().to_bytes();
        let C_m_bytes: [u8; 32] = self.C_m.compress().to_bytes();
        let C_U_Prime_bytes: [u8; 32] = self.C_U_Prime.compress().to_bytes();

        [u_bytes.as_ref(), C_m_bytes.as_ref(), C_U_Prime_bytes.as_ref()].concat()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct tmd{
    pub token_u: token,
    pub ct_id: cipher_text,
    pub ct_tag: cipher_text,
    pub Pi_send: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct tmd_prime{
    tmd: tmd,
    ct_id_prime: cipher_text,
}

#[derive(Clone)]
pub struct Report{
    token_u: token,
    Pi_rpt: Vec<u8>,
    lb: Scalar,
    share_i: Share,
    ct_tmd_prime: Vec<u8>,
    dup: RistrettoPoint,
    presentation_proof: PresentationProof,
    V: RistrettoPoint,
}

#[derive(Clone)]
pub struct Report_Prime{
    l_s: Scalar,
    share_i: Share,
    ct_tmd_prime: Vec<u8>,
    dup: RistrettoPoint,
}

// Abandoned
pub fn pke_encryption(pk: RistrettoPoint, m: &[u8]) -> (RistrettoPoint, Vec<u8>){
    let mut rng = OsRng;

    // Generate a random scalar `r`
    let r = Scalar::random(&mut rng);

    // Calculate the ephemeral public key `r * G`
    let ephemeral_pubkey = r * RISTRETTO_BASEPOINT_POINT;

    // Calculate the shared secret `r * pk`
    let shared_key = r * pk;

    // Derive the AES key from the shared secret
    let mut hasher = Sha256::new().chain(shared_key.compress().as_bytes());
    let key:[u8;32] = hasher.finalize().try_into().unwrap();
    let aes_key = Key::<Aes256Gcm>::from_slice(&key);

    // Encrypt the message using AES-GCM
    let cipher = Aes256Gcm::new(&aes_key);
    let nonce = Nonce::from_slice(b"unique nonce"); // Nonce must be unique per message
    let encrypted_message = cipher.encrypt(nonce, m).expect("encryption failure!");

    // Return the ciphertext and ephemeral public key
    (ephemeral_pubkey, encrypted_message)
}

// generate blocklist with size n randomly
pub fn blocklist_gen(n: u32) -> Vec<[u8;INPUT_LENGTH]>{
    let mut input: Vec<[u8;INPUT_LENGTH]> = vec![];
    let mut i:u32 = 0;
    while i < n{
        let hash = Sha256::digest(&i.to_le_bytes());
        input.push(hash.as_slice().try_into().expect("slice with incorrect length"));
        
        i += 1;
    }
    input
}

// 
pub fn list_set_up(regulator: &mut server, moderator: &mut server, input: Vec<[u8;INPUT_LENGTH]>) -> Vec<RistrettoPoint>{
    let randomness = [0x12; RANDOMNESS_LEN];
    let mut hashed_input: Vec<[u8;INPUT_LENGTH]> = Vec::new();
    let mut tmp: [u8; INPUT_LENGTH];
    for i in input.iter(){
        let hash = Sha256::new().chain(i);
        tmp = hash.finalize().try_into().unwrap();
        hashed_input.push(tmp);
    }
    // gen and cert both in LGen
    let K = regulator.setup(hashed_input.clone(), randomness);
    // println!();
    // let Sign = moderator.cert(hashed_input.clone(), randomness, K.clone(), Pi).unwrap();
    K
}


pub fn list_set_up_multi_threaded(regulator: &mut server, moderator: &mut server, input: Vec<[u8;INPUT_LENGTH]>) -> Vec<RistrettoPoint>{
    std::env::set_var("RAYON_NUM_THREADS", "24");
    let randomness = [0x12; RANDOMNESS_LEN];
    let mut hashed_input: Vec<[u8;INPUT_LENGTH]> = Vec::new();
    let mut tmp: [u8; INPUT_LENGTH];
    for i in input.iter(){
        let hash = Sha256::new().chain(i);
        tmp = hash.finalize().try_into().unwrap();
        hashed_input.push(tmp);
    }
    let K = regulator.setup_multi_threaded(hashed_input.clone(), randomness);
    // println!();
    K
}


pub fn user_reg(user: &mut User::User, platform: &mut Platform::Platform) -> (Scalar, Credential){
    let randomness = [0x12;RANDOMNESS_LEN];
    let mut rng = OsRng;
    let k_u = Scalar::random(&mut rng);

    user.set_k_u(k_u);
    let proof = platform.issue(k_u, randomness);
    let res = user.verify_credential_proof(platform.get_cred_pk(), proof.clone());
    assert!(res, "Issuance Verification Failed!!!");

    user.set_cred(proof.clone());

    // Because Elgamal can only encrypt points, but k_u is a scalar, so here we use k_u * g
    // Furthermore, the hashmap does not support point, so here we serialize the point to bytes
    let k_u_p = RISTRETTO_BASEPOINT_POINT * k_u;
    platform.insert_to_hashmap(&k_u_p.compress().to_bytes(), user.uid);

    (k_u, proof.credential)
}

pub fn tk_gen(user: &mut User::User, platform: &Platform::Platform) -> token{
    let k_u = user.k_u;
    let randomness = [0x12;RANDOMNESS_LEN];
    let cred_proof = user.cred.as_ref().unwrap();
    // k_u is included in the user's attribute, which is not explicitly given here
    let (presentation_proof, z, r) = user.present(platform.get_cred_pk(), &cred_proof.credential, randomness);
    user.update_z(z);
    let res = platform.verify_presentation_proof(&presentation_proof, k_u);
    assert!(res, "Presentation proof failed!!!");

    let signature = platform.sign(&presentation_proof.get_omega_bytes());
    let res = platform.verify(&presentation_proof.get_omega_bytes(), &signature);
    assert!(res, "Siangture verification failed!!!");
    let u = presentation_proof.u;
    let C_m = presentation_proof.C_m;
    let C_U_Prime = presentation_proof.C_U_Prime;
    
    token{
        u,
        C_m,
        C_U_Prime,
        signature: SerializableEcdsaSig(Arc::new(signature)),
    }
}

pub fn send(msg: &[u8], k_u: Scalar, token_u: token, pk_plt: RistrettoPoint, pk_mod: RistrettoPoint, pk_reg: RistrettoPoint, randomness: [u8;RANDOMNESS_LEN]) -> tmd{
    let mut hasher = Sha512::new().chain(msg);
    // h(msg) = random scalar
    let hash_msg_scalar = Scalar::from_hash(hasher);
    // H(msg) = g * h(msg)
    let hash_msg = RISTRETTO_BASEPOINT_POINT * hash_msg_scalar;

    // MAC = H(msg) * k_u
    let tag = hash_msg * k_u;

    let mut sho = ShoHmacSha256::new(b"JZ_SEND_20240809");
    sho.absorb_and_ratchet(&randomness);
    let r1 = sho.get_scalar();
    let r2 = sho.get_scalar();

    let ct_id = MPEnc_with_r(pk_mod, pk_plt, pk_reg, RISTRETTO_BASEPOINT_POINT * k_u, r1);
    let ct_tag = MPEnc_with_r(pk_mod, pk_plt, pk_reg, tag, r2);


    let ct_id_1 = ct_id.E1;
    let ct_id_2 = ct_id.E2;

    let ct_tag_1 = ct_tag.E1;
    let ct_tag_2 = ct_tag.E2;

    let mut st = poksho::Statement::new();
    // st.add("tag", &[("k_u", "hash_msg")]);
    st.add("ct_id_1", &[("r1", "g")]);
    st.add("ct_id_2", &[("r1", "pk_plt"), ("r1", "pk_mod"), ("r1", "pk_reg"), ("k_u", "g")]);
    st.add("ct_tag_1", &[("r2", "g")]);
    st.add("ct_tag_2", &[("r2", "pk_plt"), ("r2", "pk_mod"), ("r2", "pk_reg"), ("k_u", "hash_msg")]);

    let mut scalar_args = poksho::ScalarArgs::new();
    scalar_args.add("k_u", k_u);
    // scalar_args.add("hash_msg_scalar", hash_msg_scalar);
    scalar_args.add("r1", r1);
    scalar_args.add("r2", r2);

    let mut point_args = poksho::PointArgs::new();
    point_args.add("g", RISTRETTO_BASEPOINT_POINT);
    point_args.add("pk_plt", pk_plt);
    point_args.add("pk_mod", pk_mod);
    point_args.add("pk_reg", pk_reg);
    // point_args.add("tag", tag);
    point_args.add("hash_msg", hash_msg);
    point_args.add("ct_id_1", ct_id_1);
    point_args.add("ct_id_2", ct_id_2);
    point_args.add("ct_tag_1", ct_tag_1);
    point_args.add("ct_tag_2", ct_tag_2);

    let authenticated_message = b"JZ_SEND_20240809";

    let proof_send = st.prove(&scalar_args, &point_args, authenticated_message, &randomness).unwrap();

    let res = st.verify_proof(&proof_send, &point_args, authenticated_message).is_ok();

    let g_ku = RISTRETTO_BASEPOINT_POINT * k_u;
    let tag2 = g_ku * hash_msg_scalar;
    assert_eq!(tag, tag2, "Tag verification failed!!!");
    assert!(res, "Proof verification failed!!!");
    tmd{
        token_u,
        ct_id,
        ct_tag,
        Pi_send: proof_send,
    }

}

pub fn receive(msg: &[u8], tmd:&tmd, platform: &Platform::Platform, pk_mod: &RistrettoPoint, pk_reg: &RistrettoPoint)->bool{
    // let msg_clone = msg.clone();
    let tmd_clone = tmd.clone();
    let token = tmd.clone().token_u;
    let res = platform.verify(&token.get_omega_bytes(), &token.signature.0);
    if !res{
        return false;
    }
    let mut hasher = Sha512::new().chain(msg);
    // h(msg) = random scalar
    let hash_msg_scalar = Scalar::from_hash(hasher);
    // H(msg) = g * h(msg)
    let hash_msg = RISTRETTO_BASEPOINT_POINT * hash_msg_scalar;


    let mut st = poksho::Statement::new();
    st.add("ct_id_1", &[("r1", "g")]);
    st.add("ct_id_2", &[("r1", "pk_plt"), ("r1", "pk_mod"), ("r1", "pk_reg"), ("k_u", "g")]);
    st.add("ct_tag_1", &[("r2", "g")]);
    st.add("ct_tag_2", &[("r2", "pk_plt"), ("r2", "pk_mod"), ("r2", "pk_reg"), ("k_u", "hash_msg")]);

    let mut point_args = poksho::PointArgs::new();
    point_args.add("g", RISTRETTO_BASEPOINT_POINT);
    point_args.add("pk_plt", platform.s.pk);
    point_args.add("pk_mod", *pk_mod);
    point_args.add("pk_reg", *pk_reg);
    point_args.add("hash_msg", hash_msg);
    point_args.add("ct_id_1", tmd.ct_id.E1);
    point_args.add("ct_id_2", tmd.ct_id.E2);
    point_args.add("ct_tag_1", tmd.ct_tag.E1);
    point_args.add("ct_tag_2", tmd.ct_tag.E2);

    let authenticated_message = b"JZ_SEND_20240809";
    let res = st.verify_proof(&tmd.Pi_send, &point_args, authenticated_message).is_ok();
    if !res{
        return false;
    }

    return true;

}

pub fn report(msg: &[u8], tmd: &tmd, user: &User::User, platform: &Platform::Platform, token_u: &token, regulator: &mut server, K:&Vec<RistrettoPoint>, randomness: &[u8;RANDOMNESS_LEN], t: usize) -> Report{
    let associated_data = b"REPORT";
    let k_u = user.k_u;
    let tmd_serialized = bincode::serialize(tmd).unwrap();
    let(ek, lb, share) = TAR_share(&tmd_serialized, t, k_u, *randomness);

    let H_lb = Sha512::new().chain(lb.to_bytes());
    let H_lb = RistrettoPoint::from_hash(H_lb);
    // dup = MAC.Tag(lb, uk)
    let dup = H_lb * k_u;

    let c = client::new(regulator.pk, K.to_vec());

    let mut m_and_tmd = Vec::new();
    m_and_tmd.extend_from_slice(msg);
    m_and_tmd.extend_from_slice(&tmd_serialized);

    let ct_tmd_3 = c.encryption(msg, &m_and_tmd);
    let ct_tmd_3_ser = bincode::serialize(&ct_tmd_3).unwrap();
    let ct_tmd_prime = aes_encrypt_from_ris(ek * RISTRETTO_BASEPOINT_POINT, &ct_tmd_3_ser);

    let l_b = RISTRETTO_BASEPOINT_POINT * lb;
    let dup = k_u * l_b;

    let cred = user.cred.as_ref().unwrap();
    let credentials_system = SystemParams::get_hardcoded();
    let (presentation_proof, z, r) = user.present(platform.get_cred_pk(), &cred.credential, *randomness);
    let res = platform.verify_presentation_proof(&presentation_proof, k_u);
    assert!(res, "Presentation proof failed!!!");

    let public_key = platform.get_cred_pk();
    let X1 = public_key.X1;
    let V = (credentials_system.g * (-r)) + (X1 * z);
    let mut st = poksho::Statement::new();
    // These terms are from Chase-Perrin-Zaverucha section 3.2.
    st.add("C_m", &[("k_u", "U"), ("z", "h")]);
    st.add("V", &[("-r", "g"), ("z", "X1")]);
    st.add("dup", &[("k_u", "l_b")]);

    let mut point_args = poksho::PointArgs::new();
    point_args.add("dup", dup);
    point_args.add("l_b", l_b);
    point_args.add("C_m", presentation_proof.C_m);
    point_args.add("U", cred.credential.U);
    point_args.add("h", credentials_system.h);
    point_args.add("g", credentials_system.g);
    point_args.add("X1", X1);
    point_args.add("V", V);

    let mut scalar_args = poksho::ScalarArgs::new();
    scalar_args.add("k_u", k_u);
    scalar_args.add("z", z);
    scalar_args.add("-r", -r);

    let authenticated_message = b"JZ_REPORT_20241108";
    let Pi_rpt = st.prove(&scalar_args, &point_args, authenticated_message, randomness).unwrap();
    let res = st.verify_proof(&Pi_rpt, &point_args, authenticated_message).is_ok();
    assert!(res, "Proof verification failed!!!");

    Report{
        token_u: token_u.clone(),
        Pi_rpt,
        lb,
        share_i: Share { s: share },
        ct_tmd_prime,
        dup,
        presentation_proof,
        V
    }

}

pub fn veryfy_report(rpt: Report, platform: &Platform::Platform, k_u: Scalar, cred: IssuanceProof) -> Report_Prime{
    let res = platform.verify_presentation_proof(&rpt.presentation_proof, k_u);
    assert!(res, "Proof verification failed!!!");
    let credentials_system = SystemParams::get_hardcoded();
    let public_key = platform.get_cred_pk();
    let X1 = public_key.X1;
    // st can only prove secret sharing, consistency is not considered, because the points used in the proof are no longer available here
    let l_b = RISTRETTO_BASEPOINT_POINT * rpt.lb;
    let authenticated_message = b"JZ_REPORT_20241108";
    let mut st = poksho::Statement::new();
    // These terms are from Chase-Perrin-Zaverucha section 3.2.
    st.add("C_m", &[("k_u", "U"), ("z", "h")]);
    st.add("V", &[("-r", "g"), ("z", "X1")]);
    st.add("dup", &[("k_u", "l_b")]);
    let mut point_args = poksho::PointArgs::new();
    point_args.add("dup", rpt.dup);
    point_args.add("l_b", l_b);
    point_args.add("C_m", rpt.presentation_proof.C_m);
    point_args.add("V", rpt.V);
    point_args.add("U", cred.credential.U);
    point_args.add("h", credentials_system.h);
    point_args.add("g", credentials_system.g);  
    point_args.add("X1", X1);  
    let res = st.verify_proof(&rpt.Pi_rpt, &point_args, authenticated_message);
    assert!(res.is_ok(), "Proof verification failed!!!");

    Report_Prime{
        l_s: rpt.lb,
        share_i: rpt.share_i,
        ct_tmd_prime: rpt.ct_tmd_prime,
        dup: rpt.dup,
    }
}


pub fn inspect(ct_tmd_3: APCEOuterEncryptResult, platform: &Platform::Platform, regulator: &mut server, pk_plt: &RistrettoPoint, pk_mod: &RistrettoPoint, t: usize) -> ([u8;32], tmd, cipher_text, Vec<u8> ){
    let m_tmd = regulator.decrypt(ct_tmd_3).expect("decryption failed!");
    let m: [u8; 32] = m_tmd[..32].try_into().expect("Slice with incorrect length");
    let tmd_serialized: Vec<u8> = m_tmd[32..].to_vec();
    let tmd: tmd = bincode::deserialize(&tmd_serialized).unwrap();
    if !receive(&m, &tmd, platform, pk_mod, &regulator.pk){
        panic!("receive message failed!!!");
    }
    let ct_u_2 = MPDec1(tmd.ct_id.clone(), regulator.sk);
    let authenticated_message = b"JZ_INSPECT_20241108";
    let mut st = poksho::Statement::new();
    st.add("u2_E2", &[("ONE", "u3_E2"), ("-sk_reg", "u3_E1")]);
    let mut point_args = poksho::PointArgs::new();
    point_args.add("u3_E2", tmd.ct_id.clone().E2);
    point_args.add("u3_E1", tmd.ct_id.clone().E1);
    point_args.add("u2_E2", ct_u_2.E2);

    let mut scalar_args = poksho::ScalarArgs::new();
    scalar_args.add("ONE", Scalar::ONE);
    scalar_args.add("-sk_reg", -regulator.sk);
    let randomness:[u8;32] = [0x12;RANDOMNESS_LEN];
    let pi_d_2 = st.prove(&scalar_args, &point_args, authenticated_message, &randomness).unwrap();
    let res = st.verify_proof(&pi_d_2, &point_args, authenticated_message);
    assert!(res.is_ok(), "proof verification failed");

    (m, tmd, ct_u_2, pi_d_2)
}

pub fn review(msg: &[u8], ct_u_2: cipher_text, pi_d_2: Vec<u8>, platform: &Platform::Platform, moderator: &server, pk_reg: RistrettoPoint, tmd: tmd)->(tmd, cipher_text, Vec<u8>, cipher_text, Vec<u8>){
    let m:[u8;32] = msg.try_into().unwrap();
    if !receive(&m, &tmd, platform, &moderator.pk, &pk_reg){
        panic!("receive failed");
    }
    let authenticated_message = b"JZ_INSPECT_20241108";
    let mut st = poksho::Statement::new();
    st.add("u2_E2", &[("ONE", "u3_E2"), ("-sk_reg", "u3_E1")]);
    let mut point_args = poksho::PointArgs::new();
    point_args.add("u3_E2", tmd.ct_id.clone().E2);
    point_args.add("u3_E1", tmd.ct_id.clone().E1);
    point_args.add("u2_E2", ct_u_2.E2);
    let authenticated_message = b"JZ_INSPECT_20241108";
    let res = st.verify_proof(&pi_d_2, &point_args, authenticated_message);
    assert!(res.is_ok(), "proof verification failed");

    if !judge(msg){
        panic!("judge failed!");
    }

    let ct_u_1 = MPDec1(ct_u_2.clone(), moderator.sk);
    let authenticated_message = b"JZ_REVIEW_20241109";
    let mut st = poksho::Statement::new();
    st.add("u1_E2", &[("ONE", "u2_E2"), ("-sk_mod", "u2_E1")]);

    let mut point_args = poksho::PointArgs::new();
    point_args.add("u2_E2", ct_u_2.clone().E2);
    point_args.add("u2_E1", ct_u_2.clone().E1);
    point_args.add("u1_E2", ct_u_1.E2);

    let mut scalar_args = poksho::ScalarArgs::new();
    scalar_args.add("ONE", Scalar::ONE);
    scalar_args.add("-sk_mod", -moderator.sk);
    let randomness:[u8;32] = [0x12;RANDOMNESS_LEN];
    let pi_d_1 = st.prove(&scalar_args, &point_args, authenticated_message, &randomness).unwrap();
    (tmd, ct_u_2, pi_d_2, ct_u_1, pi_d_1)

}

pub fn judge(msg: &[u8]) -> bool{
    true
}

pub fn proc(tmd: tmd, sk_mod: Scalar) -> tmd_prime{
    let dec = ElGamalDecryption::new(sk_mod);
    let ct_id_prime = dec.process(tmd.clone().ct_id);
    tmd_prime{
        tmd,
        ct_id_prime,
    }
}

pub fn collect(rpt_primes: &Vec<Report_Prime>, t:usize) -> Option<APCEOuterEncryptResult>{
    let mut shares: Vec<(Scalar, Scalar)> = Vec::new();
    let mut L_dup: Vec<RistrettoPoint> = Vec::new();
    for i in rpt_primes.iter(){
        if L_dup.contains(&i.dup){
            continue;
        } else {
            L_dup.push(i.dup);
            shares.push(i.share_i.s);
        }
    }
    let ek = TAR_Aggregate(&shares, t);
    if ek.is_err(){
        println!("Aggregation failed!!!");
        return None;
    }
    let ek = ek.unwrap();
    let ct_tmd_3_buffer = aes_decrypt_from_ris(ek * RISTRETTO_BASEPOINT_POINT, rpt_primes[0].ct_tmd_prime.clone()).unwrap();
    let ct_tmd_3: APCEOuterEncryptResult = bincode::deserialize(&ct_tmd_3_buffer).unwrap();
    Some(ct_tmd_3)
}

pub fn dedup(rpt_prime: &Vec<Report_Prime>) -> Vec<(Scalar, Scalar)>{
    let l_s = rpt_prime[0].l_s;
    let mut shares: Vec<(Scalar, Scalar)> = Vec::new();
    let mut L_dup: Vec<RistrettoPoint> = Vec::new();
    for i in rpt_prime.iter(){
        if L_dup.contains(&i.dup){
            continue;
        } else {
            L_dup.push(i.dup);
            shares.push(i.share_i.s);
        }
    }
    //TAR_Dedup(l_s, &shares)
    shares
}

pub fn trace(m: [u8; INPUT_LENGTH], tmd: &tmd, platform: &Platform::Platform, pk_mod:&RistrettoPoint, pk_reg: &RistrettoPoint, ct_u_2: cipher_text, ct_u_1:cipher_text, pi_d_2: Vec<u8>, pi_d_1: Vec<u8>) -> Option<u64>{
    if !receive(&m, tmd, platform, pk_mod, pk_reg){
        return None;
    }
    let authenticated_message = b"JZ_INSPECT_20241108";
    let mut st = poksho::Statement::new();
    st.add("u2_E2", &[("ONE", "u3_E2"), ("-sk_reg", "u3_E1")]);
    let mut point_args = poksho::PointArgs::new();
    point_args.add("u3_E2", tmd.ct_id.clone().E2);
    point_args.add("u3_E1", tmd.ct_id.clone().E1);
    point_args.add("u2_E2", ct_u_2.E2);
    let authenticated_message = b"JZ_INSPECT_20241108";
    let res = st.verify_proof(&pi_d_2, &point_args, authenticated_message);
    assert!(res.is_ok(), "proof verification failed");

    let authenticated_message = b"JZ_REVIEW_20241109";
    let mut st = poksho::Statement::new();
    st.add("u1_E2", &[("ONE", "u2_E2"), ("-sk_mod", "u2_E1")]);
    let mut point_args = poksho::PointArgs::new();
    point_args.add("u2_E2", ct_u_2.clone().E2);
    point_args.add("u2_E1", ct_u_2.clone().E1);
    point_args.add("u1_E2", ct_u_1.clone().E2);
    let res = st.verify_proof(&pi_d_1, &point_args, authenticated_message);
    assert!(res.is_ok(), "proof verification failed");

    let k_u = MPDec2(ct_u_1, platform.s.sk);
    let res = platform.find_uid(&k_u.compress().to_bytes());
    match res{
        Some(uid) => {
            return Some(*uid);
        },
        None => {
            return None;
        }
    }
}

pub fn trace_test(m: [u8; INPUT_LENGTH], tmd: &tmd, tmd_p: &tmd_prime,  platform: &Platform::Platform, pk_mod: &RistrettoPoint) -> Option<u64>{
    // if !receive(&m, tmd, platform.clone(), pk_mod){
    //     return None;
    // }
    // let ct_id_prime = tmd_p.ct_id_prime;
    // let k_u = dec.decrypt(ct_id_prime);
    // let res = platform.find_uid(&k_u.compress().to_bytes());
    let res:Option<&u64> = Some(&123);
    match res{
        Some(uid) => {
            return Some(*uid);
        },
        None => {
            return None;
        }
    }
}


#[cfg(test)]
mod test{
    use std::{clone, ops::Index};

    use rand::RngCore;
    use serde::{Deserialize, Serialize};
    use Platform::Platform;
    use User::User;

    use super::*;

    #[test]
    fn test(){
        let input = blocklist_gen(10);
        let randomness = [0x12;RANDOMNESS_LEN];
        // label should be same
        let mut regulator = server::new(b"regulator and moderator", &randomness);
        let mut moderator = server::new(b"regulator and moderator", &randomness);
        let K = list_set_up(&mut regulator, &mut moderator, input);
        
    }

    #[test]
    fn test_reg(){
        let randomness = [0x12;RANDOMNESS_LEN];
        let mut user = User::new();
        let platform = Platform::new(randomness);
        // user_reg(user.clone(), platform.clone());
        tk_gen(&mut user, &platform);

    }

    #[test]
    fn test_send(){
        let randomness = [0x12;RANDOMNESS_LEN];
        let mut user = User::new();
        let mut platform = Platform::new(randomness);
        let mut regulator = server::new(b"regulator and moderator", &randomness);
        let mut moderator = server::new(b"regulator and moderator", &randomness);
        let msg = [0x12; INPUT_LENGTH];
        user_reg(&mut user, &mut platform);
        let token = tk_gen(&mut user, &platform.clone());
        let tmd = send(&msg, user.k_u, token.clone(), platform.s.pk, moderator.pk, regulator.pk, randomness);
        let res = receive(&msg, &tmd, &platform, &moderator.pk, &regulator.pk);
        assert!(res);
        let mut sho = ShoHmacSha256::new(b"JZ_SEND_20240809");
        sho.absorb_and_ratchet(&randomness);

        let r = sho.get_scalar();
        println!("{}", r.as_bytes().len());

        let x = sho.get_point();
        let mut buffer = Vec::new();
        let mut serializer = serde_json::Serializer::new(&mut buffer);
        
        x.serialize(&mut serializer).expect("Serialization failed");
        let serialized_str = String::from_utf8(buffer).expect("Failed to convert bytes to string");
        let deserialized: RistrettoPoint = serde_json::from_str(&serialized_str).expect("Deserialization failed");
        assert_eq!(x, deserialized, "Point conversion failed!!!");

    }

    
    #[test]
    fn test_report() {
        let input = blocklist_gen(100);
        let randomness = [0x12;RANDOMNESS_LEN];
        let msg = input.clone()[0];
        let hash = Sha256::new().chain(msg);
        let msg:[u8;32] = hash.finalize().try_into().unwrap();
        let mut regulator = server::new(b"regulator and moderator", &randomness);
        let mut moderator = server::new(b"regulator and moderator", &randomness);
        let mut platform = Platform::new(randomness);
        let pk_reg = regulator.pk;

        // generate different users
        let mut user1 = User::new();
        let mut user2 = User::new();
        let mut user3 = User::new();
        let K = list_set_up_multi_threaded(&mut regulator, &mut moderator, input.clone());
        let (k_u1, cred1) = user_reg(&mut user1, &mut platform);
        let (k_u2, cred2) = user_reg(&mut user2, &mut platform);
        let (k_u3, cred3) = user_reg(&mut user3, &mut platform);
        let token1 = tk_gen(&mut user1, &platform.clone());
        let token2 = tk_gen(&mut user2, &platform.clone());
        let token3 = tk_gen(&mut user3, &platform.clone());
        let tmd = send(&msg, user1.k_u, token1.clone(), platform.s.pk, moderator.pk, regulator.pk,randomness);

        let hpke_pk = pke::get_hpke_key_pair(&regulator).1;
        let rpt1 = report(&msg, &tmd.clone(), &user1, &platform, &token1.clone(), &mut regulator, &K.clone(), &randomness,THRESHOLD);
        let rpt2 = report(&msg, &tmd.clone(), &user1, &platform, &token1.clone(), &mut regulator, &K.clone(), &randomness,THRESHOLD);
        let rpt3 = report(&msg, &tmd.clone(), &user2, &platform, &token2.clone(), &mut regulator, &K.clone(), &randomness,THRESHOLD);
        let rpt4 = report(&msg, &tmd.clone(), &user3, &platform, &token3.clone(), &mut regulator, &K.clone(), &randomness,THRESHOLD);

        let rpt_prime1 = veryfy_report(rpt1, &platform, user1.k_u, user1.cred.clone().unwrap());
        let rpt_prime2 = veryfy_report(rpt2, &platform, user1.k_u, user1.cred.unwrap());
        let rpt_prime3 = veryfy_report(rpt3, &platform, user2.k_u, user2.cred.unwrap());
        let rpt_prime4 = veryfy_report(rpt4, &platform, user3.k_u, user3.cred.unwrap());

        let mut rpt_primes: Vec<Report_Prime> = Vec::new();
        rpt_primes.push(rpt_prime1);
        rpt_primes.push(rpt_prime2);
        rpt_primes.push(rpt_prime3);
        rpt_primes.push(rpt_prime4);

        let ct_tmd_3 = collect(&rpt_primes, THRESHOLD).unwrap();
        
        let (msg, tmd, ct_u_2, pi_d_2) = inspect(ct_tmd_3.clone(), &platform, &mut regulator, &platform.s.pk, &moderator.pk, THRESHOLD);
        // let (msg, tmd, ct_u_2, pi_d_2) = inspect(ct_tmd_3, &platform, &mut regulator, &platform.s.pk, &moderator.pk, THRESHOLD);
        let (tmd, ct_u_2, pi_d_2, ct_u_1, pi_d_1) = review(&msg, ct_u_2, pi_d_2, &platform, &moderator, regulator.pk, tmd);
        let trace_res = trace(msg, &tmd, &platform, &moderator.pk, &regulator.pk, ct_u_2.clone(), ct_u_1.clone(), pi_d_2.clone(), pi_d_1.clone());
        match trace_res{
            Some(uid) => {
                println!("The uid is: {}", uid);
                assert!(uid == user1.uid, "Trace failed!!!");
            },
            None => {
                println!("Trace failed!!!");
            }
        }

        let msg = input.clone()[0];
        let trace_res = trace(msg, &tmd, &platform, &moderator.pk, &regulator.pk, ct_u_2, ct_u_1, pi_d_2, pi_d_1);
        assert!(trace_res.is_none(), "Trace failed!!!");
    }


    // #[test]
    // fn test_trace(){
    //     let input = blocklist_gen(10);
    //     let randomness = [0x12;RANDOMNESS_LEN];
    //     let msg = input.clone()[0];
    //     let mut regulator = server::new(b"regulator and moderator", &randomness);
    //     let mut moderator = server::new(b"regulator and moderator", &randomness);
    //     let mut platform = Platform::new(randomness);

    //     let mut user1 = User::new();
    //     let mut user2 = User::new();
    //     let mut user3 = User::new();
    //     let K: Vec<RistrettoPoint> = list_set_up(&mut regulator, &mut moderator, input.clone());
    //     let (k_u1, cred1) = user_reg(&mut user1, &mut platform);
    //     let (k_u2, cred2) = user_reg(&mut user2, &mut platform);
    //     let (k_u3, cred3) = user_reg(&mut user3, &mut platform);
    //     let token1 = tk_gen(&mut user1, &platform.clone());
    //     let token2 = tk_gen(&mut user2, &platform.clone());
    //     let token3 = tk_gen(&mut user3, &platform.clone());
    //     let tmd = send(&msg, user1.k_u, token1.clone(), platform.s.pk, moderator.pk, regulator.pk, randomness);
    //     let tmd_prime: tmd_prime = proc(tmd.clone(), platform.s.sk);
    //     let trace_res = trace(msg, &tmd, &tmd_prime, &platform, &moderator.pk, &regulator.pk);
    //     match trace_res{
    //         Some(uid) => {
    //             println!("The uid is: {}", uid);
    //             assert!(uid == user1.uid, "Trace failed!!!");
    //         },
    //         None => {
    //             println!("Trace failed!!!");
    //         }
    //     }

    //     let msg2 = b"hwergwedwegfdsdahahahahlalallala";
    //     let trace_res = trace(*msg2, &tmd.clone(), &tmd_prime.clone(), &platform.clone(), &moderator.pk, &regulator.pk);
    //     assert!(trace_res.is_none(), "Trace failed!!!");
    // }

    #[test]
    fn test_sig_ser(){
        let msg = [0x12; INPUT_LENGTH];
        let randomness = [0x12;RANDOMNESS_LEN];
        let platform = Platform::new(randomness);
        let sig = platform.sign(&msg);
        assert!(platform.verify(&msg, &sig));
        let ser_sig = SerializableEcdsaSig(Arc::new(sig));

        let buffer = serde_json::to_string(&ser_sig).unwrap();
        println!("{}", buffer);
        let des: SerializableEcdsaSig = serde_json::from_str(&buffer).unwrap();
        let sig = des.0;
        assert!(platform.verify(&msg, &sig));

        let g = RISTRETTO_BASEPOINT_POINT;
        let buffer = serde_json::to_string(&g).unwrap();
        let g2: RistrettoPoint = serde_json::from_str(&buffer).unwrap();
        assert_eq!(g, g2);

        let hasher = Sha512::new().chain(b"hahawefhdewerhwergwefgsdfgsdfgsdrgerergsdfgghsdfgaha");
        let r = Scalar::from_hash(hasher);
        let g = RISTRETTO_BASEPOINT_POINT * r;
        let buffer = serde_json::to_string(&g).unwrap();
        println!("{}", buffer.as_bytes().len());
    }

    #[test]
    fn test_thread_num(){
        match std::thread::available_parallelism() {
            Ok(parallelism) => {
                let max_threads = parallelism.get();
                println!("Available parallelism (maximum threads): {}", max_threads);
            }
            Err(e) => {
                eprintln!("Failed to determine available parallelism: {}", e);
            }
        }
    }

}