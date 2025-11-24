use std::{error::Error, io::Read};
use std::{clone, fmt};
use curve25519_dalek::scalar;
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, scalar::Scalar, RistrettoPoint};
use poksho::{ShoApi, ShoHmacSha256, ShoSha256};
use serde::{Deserialize, Serialize};
use sha2::{digest::Update, Digest, Sha256, Sha512};
use zkcredential::sho::ShoExt;
use zkcredential::RANDOMNESS_LEN;
use std::time::{Instant, Duration};
use rand_core::OsRng;


#[derive(Clone)]
pub struct Share{
    pub s: (Scalar, Scalar),
    // pub d: RistrettoPoint,
    // pub Pi_ss: Vec<u8>,
}

#[derive(Debug)]
pub enum AggregationError {
    InsufficientShares,
}

impl fmt::Display for AggregationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AggregationError::InsufficientShares => write!(f, "Not enough shares to reconstruct the secret"),
        }
    }
}

pub fn TAR_share(S: &[u8], threshold: usize, k_u: Scalar, randomness:[u8;RANDOMNESS_LEN]) -> (Scalar, Scalar, (Scalar, Scalar)) {
    // r = H(S||1)
    let r = Sha512::new().chain(S).chain((1 as u32).to_le_bytes());
    let r = Scalar::from_hash(r);
    // ek = H(S||2)
    let ek = Sha512::new().chain(S).chain((2 as u32).to_le_bytes());
    let ek = Scalar::from_hash(ek);
    // l_s = H(S||3)
    let lb = Sha512::new().chain(S).chain((3 as u32).to_le_bytes());
    let lb = Scalar::from_hash(lb);

    let share = SecretShare::generate(ek, threshold);
    let mut rng = OsRng;
    let randomness = Scalar::random(&mut rng);

    let sh = share.get_share(randomness);

    (ek, lb, sh)
}

// delete deduplication
// pub fn TAR_Dedup(l_s: Scalar, shares: &Vec<Share>) -> Vec<(Scalar, Scalar)>{
//     let mut L_s: Vec<(Scalar,Scalar)> = Vec::new();
//     let mut L_t:Vec<RistrettoPoint> = Vec::new();
//     let mut st = poksho::Statement::new();
//     st.add("d", &[("k_u", "H_l_s")]);
//     let authenticated_message = b"JZ_RLSS_20240810";
//     for share in shares.iter() {
//         let mut point_args = poksho::PointArgs::new();
//         let H_l_s = Sha512::new().chain(l_s.to_bytes());
//         let H_l_s = RistrettoPoint::from_hash(H_l_s);
//         point_args.add("d", share.d);
//         point_args.add("H_l_s", H_l_s);
//         if !st.verify_proof(&share.Pi_ss, &point_args, authenticated_message).is_ok(){
//             continue;
//         }
//         if !(L_t.contains(&share.d)){
//             L_t.push(share.d);
//             L_s.push(share.s);
//         }
//     }
//     L_s
// }

pub fn TAR_Aggregate(shares: &Vec<(Scalar, Scalar)>, threshold: usize) -> Result<Scalar, AggregationError>{
    let aggr = Aggregation::new(shares.to_vec(), threshold);
    aggr.reconstruct_secret()
}

pub struct SecretShare{
    pub coefficients: Vec<Scalar>,
}

impl SecretShare {
    pub fn new(message: &[u8], threshold: usize) -> Self {
        // transform message to Scalar
        let mut arr = [0u8; 32];
        arr[..message.len()].copy_from_slice(&message);
        let secret = Scalar::from_bytes_mod_order(arr);

        // take message as randomness
        let mut hasher = Sha256::new().chain(message);
        let result = hasher.finalize();
        let mut randomness = [0u8; 32];
        randomness.copy_from_slice(&result);

        // generate polynomial coefficients
        let mut sho = ShoHmacSha256::new(b"JZ_Shamir_Secret_Sharing_20240801");
        sho.absorb_and_ratchet(&randomness);
        let mut coefficients = vec![secret];
        for _ in 1..threshold {
            coefficients.push(sho.get_scalar());
        }
        Self { coefficients }
    }

    pub fn generate(message: Scalar, threshold: usize) -> Self {
        // take message as randomness
        let mut hasher = Sha256::new().chain(message.to_bytes());
        let result = hasher.finalize();
        let mut randomness = [0u8; 32];
        randomness.copy_from_slice(&result);

        // generate polynomial coefficients
        let mut sho = ShoHmacSha256::new(b"JZ_Shamir_Secret_Sharing_20240801");
        sho.absorb_and_ratchet(&randomness);
        let mut coefficients = vec![message];
        for _ in 1..threshold {
            coefficients.push(sho.get_scalar());
        }
        Self { coefficients }
    }

    fn evaluate(&self, x: Scalar) -> Scalar {
        let mut result = Scalar::ZERO;
        let mut power = Scalar::ONE;
        for &coef in &self.coefficients {
            result += coef * power;
            power *= x;
        }
        result
    }

    pub fn get_share(&self, i: Scalar) -> (Scalar, Scalar) {
        let x = i;
        let y = self.evaluate(i);
        (x, y)
    }
}

#[derive(Debug)]
pub struct Aggregation{
    shares: Vec<(Scalar, Scalar)>,
    threshold: usize,
}

impl Aggregation {
    pub fn new(shares: Vec<(Scalar,Scalar)>, threshold: usize) ->Self{
        Self{
            shares,
            threshold,
        }
    }

    pub fn reconstruct_secret(&self) ->  Result<Scalar, AggregationError> {
        if self.shares.len() < self.threshold {
            return Err(AggregationError::InsufficientShares);
        }
        let mut secret = Scalar::ZERO;
        for (i, &(xi, yi)) in self.shares.iter().enumerate() {
            let mut li = Scalar::ONE;
    
            for (j, &(xj, _)) in self.shares.iter().enumerate() {
                if i != j {
                    li *= xj * (xj - xi).invert();
                }
            }
            secret += yi * li;
        }
        Ok(secret)
    }
}

#[cfg(test)]
mod tests {

    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, RistrettoPoint};
    use rand_core::le;
    use sha2::digest::Update;

    use super::*;

    #[test]
    fn test_shamir() {
        let mut sho = ShoHmacSha256::new(b"JZ_Shamir_Secret_Sharing_20240801");
        sho.absorb_and_ratchet(&[0x42;32]);
        let p1 = sho.get_scalar();
        let p2 = sho.get_scalar();
        let p3 = sho.get_scalar();

        // 64-bit secret as Scalar
        let message: &[u8] = b"this is a secret";


        // Threshold number of shares required to reconstruct the secret
        let threshold = 3;
        let share = SecretShare::new(message, threshold);
        let secret: Scalar = share.coefficients[0];

        // Split the secret into shares
        let s1 = share.get_share(p1);
        let s2 = share.get_share(p2);
        let s3 = share.get_share(p3);


        let selected_shares: Vec<(Scalar, Scalar)> = vec![s1, s2, s3];
        let aggr = Aggregation::new(selected_shares, threshold);

        // Reconstruct the secret
        let reconstructed_secret = aggr.reconstruct_secret().unwrap();
        assert_eq!(secret, reconstructed_secret, "The recovered secret is not equal to origin one!!!");

        // test less than threshold shares can not reconstruct
        let selected_shares: Vec<(Scalar, Scalar)> = vec![s1, s2];
        let aggr = Aggregation::new(selected_shares, threshold);
        assert!(matches!(aggr.reconstruct_secret(), Err(AggregationError)));


        // test deterministic
        let share = SecretShare::new(message, threshold);
        let s1_2 = share.get_share(p1);
        let s2_2 = share.get_share(p2);
        let s3_2 = share.get_share(p3);
        assert_eq!(s1.1, s1_2.1, "Share generation is not deterministic!!!");
        assert_eq!(s2.1, s2_2.1, "Share generation is not deterministic!!!");
        assert_eq!(s3.1, s3_2.1, "Share generation is not deterministic!!!");

 
        // test different input
        let message: &[u8] = b"this is another secret";
        let share = SecretShare::new(message, threshold);
        let secret = share.coefficients[0];
        let s1_3 = share.get_share(p1);
        let s2_3 = share.get_share(p2);
        let s3_3 = share.get_share(p3);
        assert_ne!(s1.1, s1_3.1, "Share generation is deterministic for different input!!!");
        assert_ne!(s2.1, s2_3.1, "Share generation is deterministic for different input!!!");
        assert_ne!(s3.1, s3_3.1, "Share generation is deterministic for different input!!!");
        let selected_shares: Vec<(Scalar, Scalar)> = vec![s1_3, s2_3, s3_3];
        let aggr = Aggregation::new(selected_shares, threshold);
        let reconstructed_secret = aggr.reconstruct_secret().unwrap();
        assert_eq!(secret, reconstructed_secret, "The recovered secret is identical for different input!!!");
    }

    #[test]
    fn test_time_for_chen() {
        let g: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
        let mut sho = ShoHmacSha256::new(b"JZ_Shamir_Secret_Sharing_20240801");
        sho.absorb_and_ratchet(&[0x42; 32]);
        let x: Scalar = sho.get_scalar();

        // test g^x
        let mut n:u64 = 10;
        let mut i:u64 = 0;
        let mut gx;
        let start = Instant::now();
        while i < n {
            gx = g * x;
            i += 1;
        }

        let elapsed = start.elapsed();
        let elapsed_millis_per_point:f64 = (elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis())) as f64 / n as f64;
        println!("g^x time is: {} ms", elapsed_millis_per_point);

        // test H(g^x)
        gx = g * x;
        i = 0;
        n = 1000;

        let start = Instant::now();
        while i < n{
            let gx_compress = gx.compress();
            let hash = Sha512::new().chain(gx_compress.as_bytes());
            let s = Scalar::from_hash(hash);
            i += 1;
        }

        let elapsed = start.elapsed();
        let elapsed_millis_per_point: f64 = (elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis())) as f64 / n as f64;
        println!("point hash to scalar time is: {} ms", elapsed_millis_per_point);


        // secret sharing test 
        n = 100;
        let t:[usize;5] = [4,8,16,32,64];
        let message = b"hello this is a secret";
        i = 0;
        for j in t.iter(){
            i = 0;
            let mut share: SecretShare;
            let start = Instant::now();
            share = SecretShare::new(message, *j);
            let mut one_share = share.get_share(sho.get_scalar());
            while i < n{
                one_share = share.get_share(sho.get_scalar());
                i += 1;
            }
            let elapsed = start.elapsed();
            let elapsed_millis_per_point: f64 = (elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis())) as f64 / n as f64;
            println!("Time for generate one share under threshold {} is: {} ms", j, elapsed_millis_per_point);

            i = 0;
            let mut shares = vec![one_share];
            while i < *j as u64 {
                shares.push(share.get_share(sho.get_scalar()));
                i+=1;
            }

            let aggr = Aggregation::new(shares, *j);
            i = 0;

            let start = Instant::now();
            while i < n {
                let rs = aggr.reconstruct_secret().unwrap();
                i += 1;
            }
            let elapsed = start.elapsed();
            let elapsed_millis_per_point: f64 = (elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis())) as f64 / n as f64;
            println!("Time for aggregation shares under threshold {} is: {} ms", j, elapsed_millis_per_point);
        }


        
    }

    #[test]
    fn test_rlss(){
        let mut rng = OsRng;
        let k_u1 = Scalar::random(&mut rng);
        let k_u2 = Scalar::random(&mut rng);
        let k_u3 = Scalar::random(&mut rng);
        let randomness = [0x42; RANDOMNESS_LEN];
        let S1 = b"hello this is a tmd";
        let threshold = 3;
        let (k_s, l_s, share1) = TAR_share(S1, threshold, k_u1, randomness);
        let (k_s, l_s, share2) = TAR_share(S1, threshold, k_u1, randomness);
        let (k_s, l_s, share3) = TAR_share(S1, threshold, k_u1, randomness);
        let (k_s, l_s, share4) = TAR_share(S1, threshold, k_u2, randomness);
        let (k_s, l_s, share5) = TAR_share(S1, threshold, k_u3, randomness);
        let share = SecretShare::generate(k_s, threshold);
        let shares = vec![share1, share2, share3, share4, share5];
        // let shares = TAR_Dedup(l_s, &vec![share1, share2, share3, share4, share5]);
        // println!("{}", shares.len());
        let res = TAR_Aggregate(&shares, threshold).unwrap();
        assert_eq!(res, k_s, "The recovered secret is not equal to origin one!!!");
    }

}