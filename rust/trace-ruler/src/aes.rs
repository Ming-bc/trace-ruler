use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hex_literal::hex;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

pub fn aes_256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    if plaintext.len() > 128 {
        panic!("plaintext too long");
    }
    let mut buf = [0u8; 128];
    let pt_len = plaintext.len();
    buf[..pt_len].copy_from_slice(&plaintext);
    let ct = Aes256CbcEnc::new(key.into(), iv.into())
    .encrypt_padded_vec_mut::<Pkcs7>(&plaintext);
    ct
}

pub fn aes_256_cbc_decrypt(key: &[u8; 32], iv: &[u8; 16], ciphertext: Vec<u8>) -> Vec<u8> {
    if ciphertext.len() > 128 {
        panic!("ciphertext too long");
    }
    let mut buf = [0u8; 128];
    let pt = Aes256CbcDec::new(key.into(), iv.into())
    .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
    .unwrap();
    pt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_256_cbc_encrypt() {
        let key = [0x42; 32];
        let iv = [0x24; 16];
        let plaintext = *b"heregbdrfgndthnfhtmnrthrjtyjtuksrfgethsrtjstrhjmy plaintext.";
        let ciphertext = aes_256_cbc_encrypt(&key, &iv, &plaintext);
        println!("{}", ciphertext.len());
        let pt = aes_256_cbc_decrypt(&key, &iv, ciphertext);
        assert!(pt == plaintext.to_vec());
    }
}