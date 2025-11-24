// use crate::server;
// use crate::RANDOMNESS_LEN;
// #[cfg(test)]
// mod test{
//     use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;

//     use crate::{inspect, proc, tmd_prime, trace, blocklist_gen, list_set_up, receive, report, send, tk_gen, tmd, token, user_reg, veryfy_report, INPUT_LENGTH, Report, Report_Prime};
//     use crate::User::User;
//     use crate::Platform::Platform;

//     use super::*;
//     // use test::Bencher;

//     #[test]
//     fn bench_list_gen(){
//         let i = vec![1, 10, 100];
//         let randomness = [0x12;RANDOMNESS_LEN];
//         let mut regulator = server::new(b"regulator and moderator", &randomness);
//         let mut moderator = server::new(b"regulator and moderator", &randomness);
//         for n in i{
//             let input = blocklist_gen(n);
//             let start = std::time::Instant::now();
//             let (K, Sign) = list_set_up(&mut regulator, &mut moderator, input);
//             let elapsed = start.elapsed();
//             let elapsed_millis_per_point: f64 = (elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis())) as f64;
//             println!("{} points: {} ms", n, elapsed_millis_per_point);
//         }
//     }

//     #[test]
//     fn bench_pure_list_gen(){
//         let i = vec![1, 10, 100];
//         let randomness = [0x12;RANDOMNESS_LEN];
//         let mut regulator = server::new(b"regulator and moderator", &randomness);
//         let mut moderator = server::new(b"regulator and moderator", &randomness);
//         for n in i{
//             let input = blocklist_gen(n);
//             let start = std::time::Instant::now();
//             let (K, Sign) = regulator.setup(input.clone(), randomness);
//             let elapsed = start.elapsed();
//             let elapsed_millis_per_point: f64 = (elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis())) as f64;
//             println!("{} points: {} ms", n, elapsed_millis_per_point);
//         }
//     }

//     #[test]
//     fn bench_user_reg(){
//         let randomness = [0x12;RANDOMNESS_LEN];
//         let mut user = User::new();
//         let mut platform = Platform::new(randomness);
//         // user_reg(user.clone(), platform.clone());
//         let start = std::time::Instant::now();
//         // 循环10次取平均值
//         for _ in 0..10{
//             user_reg(&mut user.clone(), &mut platform.clone());
//         }
//         let elapsed = start.elapsed();
//         let elapsed_millis_per_point: f64 = (elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis())) as f64 / 10 as f64;
//         println!("User reg: {} ms", elapsed_millis_per_point);
//     }

//     #[test]
//     fn bench_tk_gen(){
//         let randomness = [0x12;RANDOMNESS_LEN];
//         let mut user = User::new();
//         let mut platform = Platform::new(randomness);
//         // user_reg(user.clone(), platform.clone());
//         let start = std::time::Instant::now();
//         // 循环10次取平均值
//         for _ in 0..10{
//             tk_gen(&user.clone(), &platform.clone());
//         }
//         let elapsed = start.elapsed();
//         let elapsed_millis_per_point: f64 = (elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis())) as f64 / 10 as f64;
//         println!("Tk gen: {} ms", elapsed_millis_per_point);
//     }

//     #[test]
//     fn bench_send_and_receive(){
//         let randomness = [0x12;RANDOMNESS_LEN];
//         let user = User::new();
//         let platform = Platform::new(randomness);
//         let mut regulator = server::new(b"regulator and moderator", &randomness);
//         let mut moderator = server::new(b"regulator and moderator", &randomness);
//         let msg = [0x12; INPUT_LENGTH];
//         let token = tk_gen(&user.clone(), &platform.clone());
//         let start = std::time::Instant::now();
//         let mut tmd: tmd;
//         for _ in 0..10 {
//             tmd = send(&msg, user.k_u, token.clone(), platform.s.pk, moderator.pk, randomness);
//         }
//         let elapsed = start.elapsed();
//         let elapsed_millis_per_point: f64 = (elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis())) as f64 / 10 as f64;
//         println!("Send: {} ms", elapsed_millis_per_point);

//         tmd = send(&msg, user.k_u, token.clone(), platform.s.pk, moderator.pk, randomness);

//         let start = std::time::Instant::now();
//         for _ in 0..10 {
//             receive(&msg, &tmd.clone(), &platform.clone(), &moderator.pk);
//         }
//         let elapsed = start.elapsed();
//         let elapsed_millis_per_point: f64 = (elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis())) as f64 / 10 as f64;
//         println!("Receive: {} ms", elapsed_millis_per_point);
//     }

//     #[test]
//     fn bench_report(){
//         let randomness = [0x12;RANDOMNESS_LEN];
//         let mut regulator = server::new(b"regulator and moderator", &randomness);
//         let mut moderator = server::new(b"regulator and moderator", &randomness);
//         let input = blocklist_gen(10);
//         let (K, Sign) = list_set_up(&mut regulator, &mut moderator, input.clone());
//         let user = User::new();
//         let platform = Platform::new(randomness);
//         let msg = [0x12; INPUT_LENGTH];
//         let token = tk_gen(&user.clone(), &platform.clone());
//         let tmd = send(&msg, user.k_u, token.clone(), platform.s.pk, moderator.pk, randomness);
//         let start = std::time::Instant::now();
//         for _ in 0..10 {
//             report(&msg, &tmd.clone(), user.k_u, &token.clone(), &mut regulator, &K.clone(), &randomness, 3);
//         }
//         let elapsed = start.elapsed();
//         let elapsed_millis_per_point: f64 = (elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis())) as f64 / 10 as f64;
//         println!("Report: {} ms", elapsed_millis_per_point);

//         let rpt = report(&msg, &tmd.clone(), user.k_u, &token.clone(), &mut regulator, &K.clone(), &randomness, 3);

//         let start = std::time::Instant::now();
//         for _ in 0..10 {
//             veryfy_report(rpt.clone(), platform.s.pk_ecdsa.as_ref());
//         }
//         let elapsed = start.elapsed();
//         let elapsed_millis_per_point: f64 = (elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis())) as f64 / 10 as f64;
//         println!("Verify report: {} ms", elapsed_millis_per_point);
//     }

//     #[test]
//     fn bench_inspect(){
//         let thresholds: [usize; 4] = [20, 40, 60, 80];
//         let randomness = [0x12;RANDOMNESS_LEN];
//         let mut regulator = server::new(b"regulator and moderator", &randomness);
//         let mut moderator = server::new(b"regulator and moderator", &randomness);
//         let input = blocklist_gen(100);
//         let (K, Sign) = list_set_up(&mut regulator, &mut moderator, input.clone());
//         let platform = Platform::new([0x12;RANDOMNESS_LEN]);
//         let msg = input.clone()[0];
//         for t in thresholds {
//             let mut users: Vec<User> = Vec::new();
//             let mut tokens: Vec<token> = Vec::new();
//             let mut rpts_prime: Vec<Report_Prime> = Vec::new();
//             for i in 0..t{
//                 let user = User::new();
//                 let token = tk_gen(&user.clone(), &platform.clone());
//                 users.push(user.clone());
//                 tokens.push(token.clone());
//             }
//             let tmd = send(&msg, users[0].k_u, tokens[0].clone(), platform.s.pk, moderator.pk, randomness);
//             for i in 0..t{
//                 let rpt = report(&msg, &tmd.clone(), users[i].k_u, &tokens[i].clone(), &mut regulator, &K.clone(), &randomness, t);
//                 let tpr_prime = veryfy_report(rpt.clone(), platform.s.pk_ecdsa.as_ref());
//                 rpts_prime.push(tpr_prime);
//             }
//             let start = std::time::Instant::now();
//             for _ in 0..10 {
//                 inspect(&rpts_prime,&platform, &mut regulator, &platform.s.pk, &moderator.pk, t);
//             }
//             let elapsed = start.elapsed();
//             let elapsed_millis_per_point: f64 = (elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis())) as f64 / 10 as f64;
//             println!("Inspect: {} ms under threshold {}", elapsed_millis_per_point, t);
//         }
//     }

//     #[test]
//     fn bench_trace(){
//         let input = blocklist_gen(10);
//         let randomness = [0x12;RANDOMNESS_LEN];
//         let msg = input.clone()[0];
//         let mut regulator = server::new(b"regulator and moderator", &randomness);
//         let mut moderator = server::new(b"regulator and moderator", &randomness);
//         let mut platform = Platform::new(randomness);

//         let mut user = User::new();
//         let token = tk_gen(&user.clone(), &platform.clone());
//         let tmd = send(&msg, user.k_u, token.clone(), platform.s.pk, moderator.pk, randomness);
//         let tmd_prime: tmd_prime = proc(tmd.clone(), platform.s.sk);
//         let start = std::time::Instant::now();
//         for _ in 0..10 {
//             let trace_res = trace(msg, &tmd.clone(), &tmd_prime.clone(), &platform.clone(), &moderator.pk);
//         }
//         let elapsed = start.elapsed();
//         let elapsed_millis_per_point: f64 = (elapsed.as_secs() * 1000 + u64::from(elapsed.subsec_millis())) as f64 / 10 as f64;
//         println!("Trace: {} ms", elapsed_millis_per_point);

//     }
// }