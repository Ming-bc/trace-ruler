use cuckoofilter::{bucket::{Bucket, Fingerprint, BUCKET_SIZE, EMPTY_FINGERPRINT_DATA, FINGERPRINT_SIZE}, CuckooFilter, util::get_fai_from_u8};
use std::{collections::hash_map::DefaultHasher, hash::RandomState, thread::sleep};
use rand::Rng;
use rand::thread_rng;
fn main() {
    let mut T :cuckoofilter::CuckooFilter<DefaultHasher> = cuckoofilter::CuckooFilter::new();
    let n = 100000;
    let changed  = 512;
    let mut data: Vec<[u8;32]> = Vec::with_capacity(n);
    let mut rng = thread_rng();
    for i in 0..n {
        data.push(rng.gen::<[u8; 32]>());
        T.add_u8(&data[i]);
    }
    let mut T1 = T.clone();
    for _ in 0..changed {
        let r = rng.gen::<[u8; 32]>();
        T.add_u8(&r);
    }
    let mut T2 = T.clone();
    let exported_cf_1 = T1.export();
    let buckets_1 = exported_cf_1.values.chunks(BUCKET_SIZE * FINGERPRINT_SIZE).map(Bucket::from).collect::<Vec<_>>();
    let exported_cf_1 = T2.export();
    let buckets_2 = exported_cf_1.values.chunks(BUCKET_SIZE * FINGERPRINT_SIZE).map(Bucket::from).collect::<Vec<_>>();
    let mut cnt = 0;
    for(index, i) in buckets_1.iter().enumerate(){
        if i.buffer[0].data != buckets_2[index].buffer[0].data {
            cnt += 1;
        }
    }
    println!("The number of different buckets is {}", cnt);
    
}
