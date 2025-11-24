use libsignal_protocol::*;
use serde::Serialize;
use trace_ruler::tmd;
use uuid::Uuid;
use futures_util::FutureExt;
use rand::rngs::OsRng;
use std::ops::RangeFrom;
use std::time::SystemTime;
use rand::{CryptoRng, Rng};
// for seedable rng
use rand_chacha::ChaCha20Rng;
use rand::{SeedableRng};

use clap::{Arg, Command, ArgAction};

use tokio::time::error;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::net::TcpListener as TokioTcpListener;
// use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{Instant, Duration};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use std::fs::File;
use std::io::Write;


use trace_ruler::{review, collect, blocklist_gen, inspect, list_set_up, receive, report, send, tk_gen, token, trace, user_reg, veryfy_report, Platform::Platform, Report_Prime, User::User, tmd_prime, proc};
use apple_psi::{apple_psi::server};
use zkcredential::RANDOMNESS_LEN;
use std::sync::Arc;

use std::error::Error;

const CLIENT_NUM: usize = 10; // Adjust as needed
const MSGS_NUM: usize = 10;

async fn receive_data(port: u32) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let address = format!("127.0.0.1:{}", port);
    let listener = TokioTcpListener::bind(&address).await?;
    let (mut stream, _) = listener.accept().await?;
    stream.set_nodelay(true)?;
    let mut buffer = vec![0; 4096]; // Adjust buffer size as needed
    let mut data = Vec::new();

    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => break, // Connection closed
            Ok(n) => data.extend_from_slice(&buffer[..n]),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(data)
}


async fn send_data_2(port: u32, data: &[u8], wait_time: &mut Duration) -> Result<(), Box<dyn Error + Send + Sync>> {
    let address = format!("127.0.0.1:{}", port);
    let mut retries: usize = 0;
    let max_retries: usize = 500;
    let retry_interval = Duration::from_millis(1);


    let mut total_wait_time = Duration::from_secs(0); // 用来累加等待时间

    loop {
        let wait_start = Instant::now(); // 记录每次等待前的时间
        match TokioTcpStream::connect(&address).await {
            Ok(mut stream) => {
                stream.set_nodelay(true)?;
                stream.write_all(data).await?;
                *wait_time = total_wait_time;
                break;
            }
            Err(e) => {
                retries += 1;
                if retries > max_retries {
                    return Err(format!("Failed to connect to {} after {} attempts: {}", address, retries, e).into());
                }
                
                tokio::time::sleep(retry_interval).await;
                // 计算等待时间并累加
                let wait_duration = wait_start.elapsed();
                total_wait_time += wait_duration;  // 累加等待时间
                
                // println!("Wait");
            }
        }
    }

    Ok(())
}


pub fn test_in_memory_protocol_store() -> Result<InMemSignalProtocolStore, SignalProtocolError> {
    // let mut csprng = OsRng;
    let seed = [0u8; 32]; 
    let mut csprng = ChaCha20Rng::from_seed(seed);
    let identity_key = IdentityKeyPair::generate(&mut csprng);
    // Valid registration IDs fit in 14 bits.
    let registration_id: u8 = csprng.gen();

    InMemSignalProtocolStore::new(identity_key, registration_id as u32)
}

pub async fn create_pre_key_bundle<R: Rng + CryptoRng>(
    store: &mut dyn ProtocolStore,
    mut csprng: &mut R,
) -> Result<PreKeyBundle, SignalProtocolError> {
    let pre_key_pair = KeyPair::generate(&mut csprng);
    let signed_pre_key_pair = KeyPair::generate(&mut csprng);
    let kyber_pre_key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024);

    let signed_pre_key_public = signed_pre_key_pair.public_key.serialize();
    let signed_pre_key_signature = store
        .get_identity_key_pair()
        .await?
        .private_key()
        .calculate_signature(&signed_pre_key_public, &mut csprng)?;

    let kyber_pre_key_public = kyber_pre_key_pair.public_key.serialize();
    let kyber_pre_key_signature = store
        .get_identity_key_pair()
        .await?
        .private_key()
        .calculate_signature(&kyber_pre_key_public, &mut csprng)?;

    let device_id: u32 = csprng.gen();
    let pre_key_id: u32 = csprng.gen();
    let signed_pre_key_id: u32 = csprng.gen();
    let kyber_pre_key_id: u32 = csprng.gen();

    let pre_key_bundle = PreKeyBundle::new(
        store.get_local_registration_id().await?,
        device_id.into(),
        Some((pre_key_id.into(), pre_key_pair.public_key)),
        signed_pre_key_id.into(),
        signed_pre_key_pair.public_key,
        signed_pre_key_signature.to_vec(),
        *store.get_identity_key_pair().await?.identity_key(),
    )?;
    let pre_key_bundle = pre_key_bundle.with_kyber_pre_key(
        kyber_pre_key_id.into(),
        kyber_pre_key_pair.public_key.clone(),
        kyber_pre_key_signature.to_vec(),
    );

    store
        .save_pre_key(
            pre_key_id.into(),
            &PreKeyRecord::new(pre_key_id.into(), &pre_key_pair),
        )
        .await?;

    let timestamp = Timestamp::from_epoch_millis(csprng.gen());

    store
        .save_signed_pre_key(
            signed_pre_key_id.into(),
            &SignedPreKeyRecord::new(
                signed_pre_key_id.into(),
                timestamp,
                &signed_pre_key_pair,
                &signed_pre_key_signature,
            ),
        )
        .await?;

    store
        .save_kyber_pre_key(
            kyber_pre_key_id.into(),
            &KyberPreKeyRecord::new(
                kyber_pre_key_id.into(),
                Timestamp::from_epoch_millis(43),
                &kyber_pre_key_pair,
                &kyber_pre_key_signature,
            ),
        )
        .await?;
    Ok(pre_key_bundle)
}

#[tokio::main]
async fn main() -> Result<(), SignalProtocolError>  {
    let matches = Command::new("e2ee_Test")
    .version("1.0")
    .author("jz")
    .about("Does awesome things")
    .arg(Arg::new("id")
        .short('i')
        .long("id")
        .value_name("ID")
        .help("Sets an ID")
        .value_parser(clap::value_parser!(usize))
        .required(true))
    .get_matches();

    let randomness = [0x12;RANDOMNESS_LEN];
    let mut user = User::new();
    let mut platform = Platform::new(randomness);
    let mut moderator = server::new(b"regulator and moderator", &randomness);
    let mut regulator = server::new(b"regulator and moderator", &randomness);

    user_reg(&mut user, &mut platform);
    let token_u = tk_gen(&mut user, &mut platform);

    let seed = [42u8; 32]; // fixed seed to generate fixed key
    let mut rng = ChaCha20Rng::from_seed(seed);

    let id = matches.get_one::<usize>("id").expect("ID is required");
    let distribution_id = Uuid::from_u128(0xd1d1d1d1_7000_11eb_b32a_33b8a8a487a6);
    let device_id: DeviceId = 1.into();

    let trust_root = KeyPair::generate(&mut rng);
    let server_key = KeyPair::generate(&mut rng);

    let server_cert =
            ServerCertificate::new(1, server_key.public_key, &trust_root.private_key, &mut rng)?;

    let expires = Timestamp::from_epoch_millis(1605722925);

    let alice_device_id: DeviceId = 23.into();
    let bob_device_id: DeviceId = 42.into();
    let alice_e164 = "+14151111111".to_owned();
    let alice_uuid = "9d0652a3-dcc3-4d11-975f-74d61598733f".to_string();
    let bob_uuid = "796abedb-ca4e-4f18-8803-1fde5b921f9f".to_string();
    
    let alice_uuid_address = ProtocolAddress::new(alice_uuid.clone(), device_id);
    let bob_uuid_address = ProtocolAddress::new(bob_uuid.clone(), bob_device_id);
    
    let mut alice_store =test_in_memory_protocol_store()?;
    let mut bob_store = test_in_memory_protocol_store()?;

    let alice_pubkey = *alice_store.get_identity_key_pair().await?.public_key();
    let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut rng).await?;

    process_prekey_bundle(
        &bob_uuid_address,
        &mut alice_store.session_store,
        &mut alice_store.identity_store,
        &bob_pre_key_bundle,
        SystemTime::now(),
        &mut rng,
    )
    .await?;

    let sender_cert = SenderCertificate::new(
        alice_uuid.clone(),
        Some(alice_e164.clone()),
        alice_pubkey,
        alice_device_id,
        expires,
        server_cert,
        &server_key.private_key,
        &mut rng,
    )?;

    let distribution_message = create_sender_key_distribution_message(
        &alice_uuid_address,
        distribution_id,
        &mut alice_store,
        &mut rng,
    )
    .await?;

    process_sender_key_distribution_message(
        &alice_uuid_address,
        &distribution_message,
        &mut bob_store,
    )
    .await?;

    let mut ctexts: Vec<Vec<u8>> = Vec::new();
    for i in 0..CLIENT_NUM{
        for j in 0..MSGS_NUM{
            let msg: Vec<u8> = vec![0x12u8; 1024];
            // 对消息签名/封装
            let tmd = send(&msg, user.k_u, token_u.clone(), platform.s.pk, moderator.pk, regulator.pk, randomness);
            let tmd_serl = bincode::serialize(&tmd).unwrap();
            let all_msgs = bincode::serialize(&(msg, tmd_serl)).unwrap();
        
            // 使用群组加密
            let alice_message = group_encrypt(
                &mut alice_store,
                &alice_uuid_address,
                distribution_id,
                &all_msgs,
                &mut rng,
            ).await.unwrap();
        
            // 构造 UnidentifiedSenderMessageContent
            let alice_usmc = UnidentifiedSenderMessageContent::new(
                CiphertextMessageType::SenderKey,
                sender_cert.clone(),
                alice_message.serialized().to_vec(),
                ContentHint::Default,
                None,
            ).unwrap();
        
            // 进一步封装加密
            let alice_ctext = sealed_sender_encrypt_from_usmc(
                &bob_uuid_address,
                &alice_usmc,
                &alice_store.identity_store,
                &mut rng,
            ).await.unwrap();
            ctexts.push(alice_ctext);
        }
    }


    if *id == 0 {  
        // sender：每个 sender 每秒发送 MSGS_NUM 条消息到 server
        let port: u32 = 9000;
        let wait_time = Arc::new(Mutex::new(Duration::from_secs(0)));
        let total_start = Instant::now();

        
    
        let mut send_tasks = Vec::with_capacity(CLIENT_NUM);
    
        for i in 0..CLIENT_NUM {
            // 注意：对需要在任务中使用的对象进行 clone
            let wait_time_clone = Arc::clone(&wait_time);
            let mut alice_store_clone = alice_store.clone();
            let alice_uuid_address_clone = alice_uuid_address.clone();
            let token_u_clone = token_u.clone();
            let sender_cert_clone = sender_cert.clone();
            let bob_uuid_address_clone = bob_uuid_address.clone();
            let moderator_pk = moderator.pk;
            let regulator_pk = regulator.pk;
            let platform_clone = platform.clone();
            let randomness_clone = randomness;
            let mut rng_clone = rng.clone();

                                // 构造 1KB 消息
            let msg: Vec<u8> = vec![0x12u8; 1024];
            // 对消息签名/封装
            let tmd = send(&msg, user.k_u, token_u_clone.clone(), platform_clone.s.pk, moderator_pk, regulator_pk, randomness_clone);
            let tmd_serl = bincode::serialize(&tmd).unwrap();
            let all_msgs = bincode::serialize(&(msg, tmd_serl)).unwrap();
        
            // 使用群组加密
            let alice_message = group_encrypt(
                &mut alice_store_clone,
                &alice_uuid_address_clone,
                distribution_id,
                &all_msgs,
                &mut rng_clone,
            ).await.unwrap();
        
            // 构造 UnidentifiedSenderMessageContent
            let alice_usmc = UnidentifiedSenderMessageContent::new(
                CiphertextMessageType::SenderKey,
                sender_cert_clone.clone(),
                alice_message.serialized().to_vec(),
                ContentHint::Default,
                None,
            ).unwrap();
        
            // 进一步封装加密
            let alice_ctext = sealed_sender_encrypt_from_usmc(
                &bob_uuid_address_clone,
                &alice_usmc,
                &alice_store_clone.identity_store,
                &mut rng_clone,
            ).await.unwrap();

            
    
            send_tasks.push(tokio::spawn(async move {
                // 使用 tokio 的 interval 每秒触发一次循环
                let mut interval = tokio::time::interval(Duration::from_secs(1));
    
                for msg_count in 0..MSGS_NUM {
                    interval.tick().await; // 等待下一个 tick
                    let start = Instant::now();
                    {
                        let mut wt = wait_time_clone.lock().await;
                        if let Err(e) = send_data_2(port + i as u32, &alice_ctext, &mut wt).await {
                            eprintln!("sender {}: failed to send msg {} to server, error: {:?}", i, msg_count, e);
                        }
                    }
    
                    println!("sender {} finished send {} in {:?}", i, msg_count, start.elapsed());
                }
            }));
        }
    
        for task in send_tasks {
            task.await.unwrap();
        }
        println!("All sender tasks done, total elapsed time: {:?}", total_start.elapsed());
    
    } else if *id == 1 {  
        // server：针对每个 sender（监听端口：receive_port + i）接收 MSGS_NUM 条消息，再依次转发给 receiver（发送到 send_port + i）
        let receive_port: u32 = 9000;
        let send_port: u32 = 20000;
        let wait_time = Arc::new(Mutex::new(Duration::from_secs(0)));
        let mut server_tasks = Vec::with_capacity(CLIENT_NUM);
    
        for i in 0..CLIENT_NUM {
            let wait_time_clone = Arc::clone(&wait_time);
            server_tasks.push(tokio::spawn(async move {
                for msg_count in 0..MSGS_NUM {
                    // 每个 sender 对应的端口接收 MSGS_NUM 条消息
                    let received_data = receive_data(receive_port + i as u32).await?;
                    let mut wt = wait_time_clone.lock().await;
                    if let Err(e) = send_data_2(send_port + i as u32, &received_data, &mut wt).await {
                        eprintln!("server: failed to forward message from sender {} msg {}: error: {:?}", i, msg_count, e);
                    }
                }
                Ok::<(), Box<dyn Error + Send + Sync>>(())
            }));
        }
    
        // 等待所有 server 任务结束
        for task in server_tasks {
            task.await.unwrap().unwrap();
        }
        println!("Server has forwarded all messages to receiver");
    
    } else {  
        // receiver：针对每个 sender（监听端口：receive_port + i）循环接收 MSGS_NUM 条转发消息后处理
        let receive_port: u32 = 20000;
        let mut receiver_tasks = Vec::with_capacity(CLIENT_NUM);

    
        for i in 0..CLIENT_NUM {
            receiver_tasks.push(tokio::spawn(async move {
                let mut messages = Vec::with_capacity(MSGS_NUM);
                for _ in 0..MSGS_NUM {
                    let received_data = receive_data(receive_port + i as u32).await?;
                    messages.push(received_data);
                }
                Ok::<Vec<Vec<u8>>, Box<dyn Error + Send + Sync>>(messages)
            }));
        }
    
        let total_start = Instant::now();
        for (i, task) in receiver_tasks.into_iter().enumerate() {
            let messages = task.await.unwrap().unwrap();
            for (msg_index, received_data) in messages.into_iter().enumerate() {
                let mut bob_store = test_in_memory_protocol_store()?;
                let bob_pre_key_bundle = create_pre_key_bundle(&mut bob_store, &mut rng).await?;
                process_sender_key_distribution_message(
                    &alice_uuid_address,
                    &distribution_message,
                    &mut bob_store,
                )
                .await?;
                // 7. 解封第一层封装（封闭发送者加密）
                let bob_usmc = sealed_sender_decrypt_to_usmc(&received_data, &bob_store.identity_store).await.unwrap();
    
                // 8. 群组解密提取明文
                let bob_plaintext = group_decrypt(bob_usmc.contents()?, &mut bob_store, &alice_uuid_address).await.unwrap();
    
                // 9. 反序列化原始消息和附加数据，并调用处理函数
                let (msg, tmd_serl): (Vec<u8>, Vec<u8>) = bincode::deserialize(&bob_plaintext).unwrap();
                let tmd = bincode::deserialize(&tmd_serl).unwrap();
                let _r = receive(&msg, &tmd, &platform, &moderator.pk, &regulator.pk);
    
                println!("receiver {} processed message {}", i, msg_index);
            }
        }
        println!("Receiver processed all messages in {:?}", total_start.elapsed());
    }
    
    Ok(())

}