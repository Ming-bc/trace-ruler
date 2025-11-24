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

    if *id == 0{ // sender
        // 1kb msg
        let start = Instant::now();
        let msg: Vec<u8> = vec![0x12u8; 1024];
        
        let alice_message = group_encrypt(
            &mut alice_store,
            &alice_uuid_address,
            distribution_id,
            &msg,
            &mut rng,
        )
        .await?;

        let alice_usmc = UnidentifiedSenderMessageContent::new(
        CiphertextMessageType::SenderKey,
        sender_cert.clone(),
        alice_message.serialized().to_vec(),
        ContentHint::Default,
        None,
        )?;

        let alice_ctext = sealed_sender_encrypt_from_usmc(
            &bob_uuid_address,
            &alice_usmc,
            &alice_store.identity_store,
            &mut rng,
        )
        .await?;

        // println!("{:?}", alice_ctext);
        // send message to server
        let port: u32 = 8001;
        let wait_time = Arc::new(Mutex::new(Duration::from_secs(0)));
        let mut send_tasks: Vec<JoinHandle<()>> = Vec::new();
        let wt_clone = Arc::clone(&wait_time);
        send_tasks.push(tokio::spawn(async move{
            let mut r = wt_clone.lock().await;
            if let Err(e) = send_data_2(port, &alice_ctext, &mut r).await {
                eprintln!("failed to send msg to server");
            }
        }));

        for task in send_tasks {
            task.await.unwrap();
        }

        println!("wait time {:?}", wait_time);
        println!("send time {:?}", start.elapsed());

    } else if *id == 1{ // server
        // send message to receiver
        let mut receive_tasks:  Vec< JoinHandle< Result< Vec<u8>, Box<dyn Error + Send + Sync> > > > = Vec::new();
        let port: u32 = 8001;
        let port2: u32 = 8002;
        receive_tasks.push(tokio::spawn(async move{
            let received_data = receive_data(port).await?;
            Ok((received_data))
        }));
        let wait_time = Arc::new(Mutex::new(Duration::from_secs(0)));

        let mut send_tasks: Vec<JoinHandle<()>> = Vec::new();
        for task in receive_tasks{
            let received_data = task.await.unwrap().unwrap();
            // println!("{:?}", received_data);
            let wt_clone = Arc::clone(&wait_time);
            send_tasks.push(tokio::spawn(async move{
                let mut r = wt_clone.lock().await;
                if let Err(e) = send_data_2(port2, &received_data, &mut r).await {
                    eprintln!("failed to send msg to receiver");
                }
            }));
            // println!("{:?}",received_data);
        }

        for task in send_tasks{
            task.await.unwrap();
        }
        println!("wait time {:?}", wait_time);
    } else {  // receiver
        // reveive message and decrypt
        let mut receive_tasks:  Vec< JoinHandle< Result< Vec<u8>, Box<dyn Error + Send + Sync> > > > = Vec::new();
        let port: u32 = 8002;
        receive_tasks.push(tokio::spawn(async move{
            let received_data = receive_data(port).await?;
            Ok((received_data))
        }));

        let mut send_tasks: Vec<JoinHandle<()>> = Vec::new();
        let mut received_data: Vec<u8> = Vec::new();

        let start = Instant::now();
        for task in receive_tasks{
            received_data = task.await.unwrap().unwrap();
        }

        // println!("{:?}", received_data);
 
        let bob_usmc = sealed_sender_decrypt_to_usmc(&received_data, &bob_store.identity_store).await?;
        let bob_plaintext = group_decrypt(bob_usmc.contents()?, &mut bob_store, &alice_uuid_address).await?;
        println!("receive time {:?}", start.elapsed());
    
    }
    Ok(())

}
