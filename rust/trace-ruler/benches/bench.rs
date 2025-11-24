use bincode::de;
use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, black_box};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::{scalar, RistrettoPoint, Scalar};
use elgamal::encryption::ElGamalDecryption;
use poksho::ShoApi;
use trace_ruler::{list_set_up_multi_threaded, pke, trace_test};
use zkcredential::sho::ShoExt;
use zkcredential::RANDOMNESS_LEN;
use trace_ruler::{review, collect, blocklist_gen, inspect, list_set_up, receive, report, send, tk_gen, token, trace, user_reg, veryfy_report, Platform::Platform, Report_Prime, User::User, tmd_prime, proc};
use apple_psi::{apple_psi::INPUT_LENGTH, apple_psi::server};
use elgamal::encryption::cipher_text;
use sha2::{Digest,digest::Update, Sha512, Sha256};

fn bench_point_mul(c: &mut Criterion){
    let mut group = c.benchmark_group("trace-ruler");
    let g = RISTRETTO_BASEPOINT_POINT;
    let mut input_sho = poksho::ShoSha256::new(b"test");
    let s = input_sho.get_scalar();

    group.bench_function("point multiplication", |b| {
        b.iter(|| {
            // 执行基点乘法，并使用 black_box 防止编译器优化
            let _ = black_box(s) * black_box(g);
        });
    });


    group.finish();
}

// 100000:46.557s
// 1000000: 764.55s
// 10000000: time:   [6019.4 s 6519.6 s 7220.6 s]
fn bench_list_gen(c: &mut Criterion){
    let mut group = c.benchmark_group("trace-ruler");
    group.sample_size(10);
    let randomness = [0x12;RANDOMNESS_LEN];
    let mut regulator = server::new(b"regulator and moderator", &randomness);
    let mut moderator = server::new(b"regulator and moderator", &randomness);
    for i in [10000, 100000, 1000000, 10000000]{
        let input = blocklist_gen(i);
        group.bench_function(BenchmarkId::new("list_gen", i), |b|{
            b.iter(||{
                list_set_up_multi_threaded(&mut regulator, &mut moderator, input.clone())
            });
        });
    }
    group.finish();
}

fn bench(c: &mut Criterion){
    let mut group = c.benchmark_group("trace-ruler");
    let randomness = [0x12;RANDOMNESS_LEN];
    let mut user = User::new();
    let mut platform = Platform::new(randomness);
    let mut moderator = server::new(b"regulator and moderator", &randomness);
    let mut regulator = server::new(b"regulator and moderator", &randomness);


    // let user_reg = || user_reg(&mut user.clone(), &mut platform.clone());
    group.bench_function("user_reg", |b|{
        b.iter(|| user_reg(&mut user, &mut platform));
    });

    // let token_gen = || tk_gen(&user, &platform);
    group.bench_function("token_gen", |b|{
        b.iter(|| tk_gen(&mut user, &mut platform));
    });


    let msg = [0x12; INPUT_LENGTH];
    let token_u = tk_gen(&mut user, &mut platform);
    // let send_msg = || send(&msg, user.k_u, token_u.clone(), platform.s.pk, moderator.pk, randomness);
    group.bench_function("send", |b|{
        b.iter(|| send(&msg, user.k_u, token_u.clone(), platform.s.pk, moderator.pk, regulator.pk, randomness));
    });


    let tmd = send(&msg, user.k_u, token_u.clone(), platform.s.pk, moderator.pk, regulator.pk, randomness);
    let receive_msg = || receive(&msg, &tmd, &platform, &moderator.pk, &regulator.pk);
    group.bench_function("receive", |b|{
            b.iter(receive_msg);
    });


    let input = blocklist_gen(10);
    let K = list_set_up(&mut regulator, &mut moderator, input.clone());
    let msg = input.clone()[0];
    let hash = Sha256::new().chain(msg);
    let msg:[u8;32] = hash.finalize().try_into().unwrap();
    // let t = 20;
    let mut regulator = server::new(b"regulator and moderator", &randomness);
    // group.bench_function("report", |b|{
    //     b.iter(|| {
    //         report(&msg, &tmd, &user, &platform, &token_u, &mut regulator,&K, &randomness, t)
    //     });
    // });

    // let rpt = report(&msg, &tmd, &user, &platform, &token_u, &mut regulator, &K, &randomness, t);
    // // let vrfy_rpt = || veryfy_report(rpt.clone(), platform.s.pk_ecdsa.as_ref());
    // group.bench_function("verify_report", |b|{
    //     b.iter(|| veryfy_report(rpt.clone(), &platform, user.k_u, user.cred.clone().unwrap()));
    // });

    for t in [20, 40, 60, 80]{
        let mut users: Vec<User> = Vec::new();
        let mut tokens: Vec<token> = Vec::new();
        let mut rpts_prime: Vec<Report_Prime> = Vec::new();
        for i in 0..t{
            let mut user = User::new();
            user_reg(&mut user, &mut platform);
            let token = tk_gen(&mut user, &mut platform);
            users.push(user.clone());
            tokens.push(token.clone());
        }
        let tmd = send(&msg, users[0].k_u, token_u.clone(), platform.s.pk, moderator.pk, regulator.pk, randomness);

        for i in 0..t{
            let rpt = report(&msg, &tmd, &users[i], &platform, &tokens[i], &mut regulator, &K, &randomness, t);
            let rpt_prime = veryfy_report(rpt.clone(), &platform, users[i].k_u, users[i].cred.clone().unwrap());
            rpts_prime.push(rpt_prime);
        }
        // let mut r_clone = regulator.clone();
        group.bench_function(BenchmarkId::new("collect", t), |b|{
            b.iter(||{
                collect(&rpts_prime, t).unwrap()
            });
        });
        let ct_tmd_3 = collect(&rpts_prime, t).unwrap();
        group.bench_function(BenchmarkId::new("inspect", t), |b|{
            b.iter(|| {
                inspect(ct_tmd_3.clone(), &platform, &mut regulator, &platform.s.pk, &moderator.pk, t)
            });
        });
        let (msg, tmd, ct_u_2, pi_d_2) = inspect(ct_tmd_3.clone(), &platform, &mut regulator, &platform.s.pk, &moderator.pk, t);
        group.bench_function(BenchmarkId::new("review", t), |b|{
            b.iter(||{
                review(&msg, ct_u_2.clone(), pi_d_2.clone(), &platform, &moderator, regulator.pk, tmd.clone())
            });
        });
        let (tmd, ct_u_2, pi_d_2, ct_u_1, pi_d_1) = review(&msg, ct_u_2.clone(), pi_d_2.clone(), &platform, &moderator, regulator.pk, tmd);
        group.bench_function(BenchmarkId::new("trace", t),|b|{
            b.iter(||{
                trace(msg, &tmd, &platform, &moderator.pk, &regulator.pk, ct_u_2.clone(), ct_u_1.clone(), pi_d_2.clone(), pi_d_1.clone())
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);