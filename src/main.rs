use block_padding::{Pkcs7, RawPadding};
use cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use des::Des;
use std::fs::File;
use std::io::{Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let plaintext_file = std::env::var("FILE_NAME").unwrap_or("plaintext_file.txt".to_string());
    //let plaintext_file = "plaintext_file.txt";
    let encrypted_file = "encrypted_file.des";
    let decrypted_file = "decrypted_file.txt";

    des_encrypt(plaintext_file.as_str(), encrypted_file)?;
    des_decrypt(encrypted_file, decrypted_file)?;

    Ok(())
}

fn des_encrypt(
    plaintext_file: &str,
    encrypted_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // The key used for DES encryption/decryption
    let key = b"***********"; // 8-byte key

    // Read the plaintext file
    let mut plaintext_file = File::open(plaintext_file)?;
    let mut plaintext_data = Vec::new();
    plaintext_file.read_to_end(&mut plaintext_data)?;

    // Calculate the required padding size
    let block_size = 8;
    let padding_size = block_size - (plaintext_data.len() % block_size);
    let total_size = plaintext_data.len() + padding_size;

    // Create a buffer with the plaintext data and the necessary padding
    let mut buffer = vec![0u8; total_size];
    buffer[..plaintext_data.len()].copy_from_slice(&plaintext_data);
    Pkcs7::raw_pad(&mut buffer, plaintext_data.len());

    // Create the DES encryption cipher
    let key = GenericArray::from_slice(key);
    let cipher = Des::new(key);

    // Encrypt the data
    let mut encrypted_data = Vec::new();
    for chunk in buffer.chunks(block_size) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.encrypt_block(&mut block);
        encrypted_data.extend_from_slice(&block);
    }

    // Write the encrypted data to a new file
    let mut file = File::create(encrypted_file)?;
    file.write_all(&encrypted_data)?;

    println!(
        "Encryption successful! Encrypted data written to {}",
        encrypted_file
    );

    Ok(())
}

fn des_decrypt(encrypted_file: &str, decrypted_file: &str) -> std::io::Result<()> {
    // The key used for DES encryption/decryption
    let key = b"**********"; // 8-byte key

    // Read the encrypted file
    let mut file = File::open(encrypted_file)?;
    let mut encrypted_data = Vec::new();
    file.read_to_end(&mut encrypted_data)?;

    // Create the DES decryption cipher
    let key = GenericArray::from_slice(key);
    let cipher = Des::new(key);

    // Decrypt the data
    let mut decrypted_data = Vec::new();
    for chunk in encrypted_data.chunks(8) {
        let mut block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        decrypted_data.extend_from_slice(&block);
    }

    // Remove padding
    let unpadded_data = Pkcs7::raw_unpad(&decrypted_data).expect("Failed to unpad data");

    // Write the decrypted data to a new file
    let mut file = File::create(decrypted_file)?;
    file.write_all(unpadded_data)?;

    println!(
        "Decryption successful! Decrypted data written to {}",
        decrypted_file
    );

    Ok(())
}
