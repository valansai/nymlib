// MIT License
// Copyright (c) Valan Sai 2025
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::rand::rand_bytes;

use openssl::pkey::{
    PKey, 
    Private, 
    Public
};


use openssl::sign::{
    Signer, 
    Verifier
};

use serialize::{
    DataStream, 
    GetHash, 
    Serialize
};

use zeroize::Zeroize; 

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

pub const ALGORITHM_ECDSA: u8 = 1;
pub const ALGORITHM_RSA: u8 = 2;
pub const ALGORITHM_ECDHE: u8 = 3;

const MIN_RSA_KEY_SIZE: u32 = 3072;

#[derive(Debug)]
pub enum CryptoError {
    ErrorKeyGeneration { message: String },
    ErrorSerialization { message: String },
    ErrorSigning { message: String },
    ErrorVerification { message: String },
    ErrorInvalidKey { message: String },
    ErrorInvalidInput { message: String },
    ErrorOpenSSL { message: String },
    ErrorBufferOverflow { message: String },
}

impl CryptoError {
    pub fn new_error_key_generation(msg: &str) -> Self {
        CryptoError::ErrorKeyGeneration { message: msg.to_string() }
    }
    pub fn new_error_serialization(msg: &str) -> Self {
        CryptoError::ErrorSerialization { message: msg.to_string() }
    }
    pub fn new_error_signing(msg: &str) -> Self {
        CryptoError::ErrorSigning { message: msg.to_string() }
    }
    pub fn new_error_verification(msg: &str) -> Self {
        CryptoError::ErrorVerification { message: msg.to_string() }
    }
    pub fn new_error_invalid_key(msg: &str) -> Self {
        CryptoError::ErrorInvalidKey { message: msg.to_string() }
    }
    pub fn new_error_invalid_input(msg: &str) -> Self {
        CryptoError::ErrorInvalidInput { message: msg.to_string() }
    }
    pub fn new_error_openssl(err: ErrorStack) -> Self {
        CryptoError::ErrorOpenSSL { message: format!("OpenSSL error: {}", err) }
    }
    pub fn new_error_buffer_overflow(msg: &str) -> Self {
        CryptoError::ErrorBufferOverflow { message: msg.to_string() }
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////// ECDSA ///////////////////////////////////////////////////////////

#[derive(Debug, Clone, PartialEq)]
pub struct EcKeyPair {
    pub pubkey: Vec<u8>,
    pub privkey: Vec<u8>,
}

impl Default for EcKeyPair {
    fn default() -> Self {
        EcKeyPair { pubkey: vec![], privkey: vec![] }
    }
}

impl Drop for EcKeyPair {
    fn drop(&mut self) {
        self.privkey.zeroize(); 
    }
}

impl EcKeyPair {
    pub fn new() -> Result<Self, CryptoError> {
        let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP256K1)
            .map_err(|e| CryptoError::new_error_key_generation(&format!("Failed to create EC group: {}", e)))?;
        let ec_key = openssl::ec::EcKey::generate(&group)
            .map_err(|e| CryptoError::new_error_key_generation(&format!("Failed to generate EC key: {}", e)))?;
        
    

        let pkey = PKey::from_ec_key(ec_key.clone())
            .map_err(|e| CryptoError::new_error_key_generation(&format!("Failed to create PKey: {}", e)))?;
        let pubkey = ec_key
            .public_key_to_der()
            .map_err(|e| CryptoError::new_error_serialization(&format!("Failed to serialize public key: {}", e)))?;
        let mut privkey = ec_key
            .private_key_to_der()
            .map_err(|e| CryptoError::new_error_serialization(&format!("Failed to serialize private key: {}", e)))?;
        
        let keypair = EcKeyPair { pubkey, privkey: privkey.clone() };
        privkey.zeroize(); // Clear temporary buffer
        Ok(keypair)
    }

    pub fn fingerprint(&self) -> Result<[u8; 32], CryptoError> {
        if self.pubkey.is_empty() {
            return Err(CryptoError::new_error_invalid_key("Empty public key"));
        }
        Ok(serialize::SerializeHash(self))
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////// RSA ////////////////////////////////////////////////////////////

#[derive(Debug, Clone, PartialEq)]
pub struct RsaKeyPair {
    pub pubkey: Vec<u8>,
    pub privkey: Vec<u8>,
}

impl Default for RsaKeyPair {
    fn default() -> Self {
        RsaKeyPair { pubkey: vec![], privkey: vec![] }
    }
}

impl Drop for RsaKeyPair {
    fn drop(&mut self) {
        self.privkey.zeroize(); 
    }
}

impl RsaKeyPair {
    pub fn new() -> Result<Self, CryptoError> {
        let rsa = openssl::rsa::Rsa::generate(MIN_RSA_KEY_SIZE)
            .map_err(|e| CryptoError::new_error_key_generation(&format!("Failed to generate RSA key: {}", e)))?;

        // Validate key size (convert bytes to bits)
        if (rsa.size() * 8) < MIN_RSA_KEY_SIZE {
            return Err(CryptoError::new_error_key_generation("Generated RSA key size too small"));
        }

        let pkey = PKey::from_rsa(rsa)
            .map_err(|e| CryptoError::new_error_key_generation(&format!("Failed to create PKey: {}", e)))?;
        let pubkey = pkey
            .public_key_to_der()
            .map_err(|e| CryptoError::new_error_serialization(&format!("Failed to serialize public key: {}", e)))?;
        let mut privkey = pkey
            .private_key_to_der()
            .map_err(|e| CryptoError::new_error_serialization(&format!("Failed to serialize private key: {}", e)))?;
        
        let keypair = RsaKeyPair { pubkey, privkey: privkey.clone() };
        privkey.zeroize(); 
        Ok(keypair)
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.is_empty() {
            return Err(CryptoError::new_error_invalid_input("Empty data provided for encryption"));
        }

        let rsa = openssl::rsa::Rsa::public_key_from_der(&self.pubkey)
            .map_err(|e| CryptoError::new_error_invalid_key(&format!("Failed to parse RSA public key: {}", e)))?;

        let mut buf = vec![0; rsa.size() as usize];
        let len = rsa
            .public_encrypt(data, &mut buf, openssl::rsa::Padding::PKCS1_OAEP)
            .map_err(|e| CryptoError::new_error_openssl(e))?;
        buf.truncate(len);
        Ok(buf)
    }

    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if encrypted_data.is_empty() {
            return Err(CryptoError::new_error_invalid_input("Empty encrypted data provided"));
        }

        let rsa = openssl::rsa::Rsa::private_key_from_der(&self.privkey)
            .map_err(|e| CryptoError::new_error_invalid_key(&format!("Failed to parse RSA private key: {}", e)))?;

        if encrypted_data.len() != rsa.size() as usize {
            return Err(CryptoError::new_error_invalid_input(
                &format!("Invalid encrypted data length: expected {}, got {}", rsa.size(), encrypted_data.len())
            ));
        }

        let mut buf = vec![0; rsa.size() as usize];
        let len = rsa
            .private_decrypt(encrypted_data, &mut buf, openssl::rsa::Padding::PKCS1_OAEP)
            .map_err(|e| CryptoError::new_error_openssl(e))?;
        buf.truncate(len);
        Ok(buf)
    }

    pub fn fingerprint(&self) -> Result<[u8; 32], CryptoError> {
        if self.pubkey.is_empty() {
            return Err(CryptoError::new_error_invalid_key("Empty public key"));
        }
        Ok(serialize::SerializeHash(self))
    }
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////// Keyring //////////////////////////////////////////////////////////

#[derive(Debug)]
pub struct EncryptedPackage {
    pub encrypted_key: Vec<u8>,
    pub ephemeral_pubkey: Vec<u8>,
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl EncryptedPackage {
    pub fn has_ephemeral_pubkey(&self) -> bool {
        !self.ephemeral_pubkey.is_empty() && self.ephemeral_pubkey.iter().any(|&b| b != 0)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Keyring {
    pub ec_keypair: EcKeyPair,
    pub rsa_keypair: RsaKeyPair,
}

impl Default for Keyring {
    fn default() -> Self {
        Keyring {
            ec_keypair: EcKeyPair::default(),
            rsa_keypair: RsaKeyPair::default(),
        }
    }
}

impl Drop for Keyring {
    fn drop(&mut self) {
    }
}

impl Keyring {
    pub fn new() -> Result<Self, CryptoError> {
        Ok(Keyring {
            ec_keypair: EcKeyPair::new()?,
            rsa_keypair: RsaKeyPair::new()?,
        })
    }

    // Helper function to derive shared secret for ECDHE
    fn derive_shared_secret(
        sender_privkey: &[u8],
        receiver_pubkey: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let priv_ec = openssl::ec::EcKey::private_key_from_der(sender_privkey)
            .map_err(|e| CryptoError::new_error_invalid_key(&format!("Failed to parse sender private key: {}", e)))?;
        let pub_ec = openssl::ec::EcKey::public_key_from_der(receiver_pubkey)
            .map_err(|e| CryptoError::new_error_invalid_key(&format!("Failed to parse receiver public key: {}", e)))?;

        let priv_pkey = PKey::from_ec_key(priv_ec)
            .map_err(|e| CryptoError::new_error_key_generation(&format!("Failed to create PKey from sender private key: {}", e)))?;
        let pub_pkey = PKey::from_ec_key(pub_ec)
            .map_err(|e| CryptoError::new_error_key_generation(&format!("Failed to create PKey from receiver public key: {}", e)))?;

        let mut deriver = openssl::derive::Deriver::new(&priv_pkey)
            .map_err(|e| CryptoError::new_error_openssl(e))?;
        deriver
            .set_peer(&pub_pkey)
            .map_err(|e| CryptoError::new_error_openssl(e))?;
        let shared_secret = deriver
            .derive_to_vec()
            .map_err(|e| CryptoError::new_error_openssl(e))?;

        let mut hasher = openssl::hash::Hasher::new(MessageDigest::sha256())
            .map_err(|e| CryptoError::new_error_openssl(e))?;
        hasher
            .update(&shared_secret)
            .map_err(|e| CryptoError::new_error_openssl(e))?;
        let digest = hasher
            .finish()
            .map_err(|e| CryptoError::new_error_openssl(e))?;
        Ok(digest.to_vec())
    }

    // New encrypt function using sender and receiver keyrings
    pub fn encrypt(
        sender: &Keyring,
        receiver: &Keyring,
        flags: u8,
        plaintext: &[u8],
    ) -> Result<EncryptedPackage, CryptoError> {
        if plaintext.is_empty() {
            return Err(CryptoError::new_error_invalid_input("Empty plaintext provided"));
        }

        match flags {
            ALGORITHM_RSA => {
                let mut aes_key = vec![0u8; 32];
                let mut iv = vec![0u8; 12];

                rand_bytes(&mut aes_key)
                    .map_err(|e| CryptoError::new_error_openssl(e))?;
                rand_bytes(&mut iv)
                    .map_err(|e| CryptoError::new_error_openssl(e))?;

                let cipher = openssl::symm::Cipher::aes_256_gcm();
                let mut crypter = openssl::symm::Crypter::new(
                    cipher,
                    openssl::symm::Mode::Encrypt,
                    &aes_key,
                    Some(&iv),
                )
                .map_err(|e| CryptoError::new_error_openssl(e))?;

                let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
                let mut tag = vec![0; 16];
                let mut count = crypter
                    .update(plaintext, &mut ciphertext)
                    .map_err(|e| CryptoError::new_error_openssl(e))?;
                count += crypter
                    .finalize(&mut ciphertext[count..])
                    .map_err(|e| CryptoError::new_error_openssl(e))?;
                crypter.get_tag(&mut tag).map_err(|e| CryptoError::new_error_openssl(e))?;
                ciphertext.truncate(count);
                ciphertext.extend_from_slice(&tag);

                let encrypted_key = receiver.rsa_keypair.encrypt(&aes_key)?;

                Ok(EncryptedPackage {
                    encrypted_key,
                    ephemeral_pubkey: vec![],
                    iv,
                    ciphertext,
                })
            }
            ALGORITHM_ECDHE => {
                let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::SECP256K1)
                    .map_err(|e| CryptoError::new_error_key_generation(&format!("Failed to create EC group: {}", e)))?;
                let eph_key = openssl::ec::EcKey::generate(&group)
                    .map_err(|e| CryptoError::new_error_key_generation(&format!("Failed to generate ephemeral key: {}", e)))?;

                let eph_pub_der = eph_key
                    .public_key_to_der()
                    .map_err(|e| CryptoError::new_error_serialization(&format!("Failed to serialize ephemeral public key: {}", e)))?;

                let mut eph_priv_der = eph_key.private_key_to_der()
                    .map_err(|e| CryptoError::new_error_serialization(&format!("Failed to serialize ephemeral private key: {}", e)))?;

                let aes_key = Self::derive_shared_secret(
                    &eph_priv_der,
                    &receiver.ec_keypair.pubkey,
                )?;

                eph_priv_der.zeroize();


                let mut iv = vec![0u8; 12];
                rand_bytes(&mut iv)
                    .map_err(|e| CryptoError::new_error_openssl(e))?;

                let cipher = openssl::symm::Cipher::aes_256_gcm();
                let mut crypter = openssl::symm::Crypter::new(
                    cipher,
                    openssl::symm::Mode::Encrypt,
                    &aes_key[..32],
                    Some(&iv),
                )
                .map_err(|e| CryptoError::new_error_openssl(e))?;

                let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
                let mut tag = vec![0; 16];
                let mut count = crypter
                    .update(plaintext, &mut ciphertext)
                    .map_err(|e| CryptoError::new_error_openssl(e))?;
                count += crypter
                    .finalize(&mut ciphertext[count..])
                    .map_err(|e| CryptoError::new_error_openssl(e))?;
                crypter.get_tag(&mut tag).map_err(|e| CryptoError::new_error_openssl(e))?;
                ciphertext.truncate(count);
                ciphertext.extend_from_slice(&tag);

                Ok(EncryptedPackage {
                    encrypted_key: vec![],
                    ephemeral_pubkey: eph_pub_der,
                    iv,
                    ciphertext,
                })
            }
            _ => Err(CryptoError::new_error_invalid_input("Invalid encryption algorithm flag")),
        }
    }

    // New decrypt function using sender and receiver keyrings
    pub fn decrypt(
        receiver: &Keyring,
        sender: &Keyring,
        flags: u8,
        package: &EncryptedPackage,
    ) -> Result<Vec<u8>, CryptoError> {
        if package.ciphertext.len() < 16 {
            return Err(CryptoError::new_error_invalid_input("Ciphertext too short to contain authentication tag"));
        }

        match flags {
            ALGORITHM_RSA => {
                let aes_key = receiver.rsa_keypair.decrypt(&package.encrypted_key)?;

                let cipher = openssl::symm::Cipher::aes_256_gcm();
                let (ciphertext, tag) = package.ciphertext.split_at(package.ciphertext.len() - 16);
                if package.iv.len() != 12 {
                    return Err(CryptoError::new_error_invalid_input("Invalid IV length for AES-GCM"));
                }
                let mut crypter = openssl::symm::Crypter::new(
                    cipher,
                    openssl::symm::Mode::Decrypt,
                    &aes_key,
                    Some(&package.iv),
                )
                .map_err(|e| CryptoError::new_error_openssl(e))?;
                crypter.set_tag(&tag).map_err(|e| CryptoError::new_error_openssl(e))?;

                let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
                let mut count = crypter
                    .update(ciphertext, &mut plaintext)
                    .map_err(|e| CryptoError::new_error_openssl(e))?;
                count += crypter
                    .finalize(&mut plaintext[count..])
                    .map_err(|e| CryptoError::new_error_openssl(e))?;
                plaintext.truncate(count);
                Ok(plaintext)
            }
            ALGORITHM_ECDHE => {
                if !package.has_ephemeral_pubkey() {
                    return Err(CryptoError::new_error_invalid_key("Missing or invalid ephemeral public key"));
                }

                let aes_key = Self::derive_shared_secret(
                    &receiver.ec_keypair.privkey,
                    &package.ephemeral_pubkey,
                )?;

                let cipher = openssl::symm::Cipher::aes_256_gcm();
                let (ciphertext, tag) = package.ciphertext.split_at(package.ciphertext.len() - 16);
                if package.iv.len() != 12 {
                    return Err(CryptoError::new_error_invalid_input("Invalid IV length for AES-GCM"));
                }
                let mut crypter = openssl::symm::Crypter::new(
                    cipher,
                    openssl::symm::Mode::Decrypt,
                    &aes_key[..32],
                    Some(&package.iv),
                )
                .map_err(|e| CryptoError::new_error_openssl(e))?;
                crypter.set_tag(&tag).map_err(|e| CryptoError::new_error_openssl(e))?;

                let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
                let mut count = crypter
                    .update(ciphertext, &mut plaintext)
                    .map_err(|e| CryptoError::new_error_openssl(e))?;
                count += crypter
                    .finalize(&mut plaintext[count..])
                    .map_err(|e| CryptoError::new_error_openssl(e))?;
                plaintext.truncate(count);
                Ok(plaintext)
            }
            _ => Err(CryptoError::new_error_invalid_input("Invalid decryption algorithm flag")),
        }
    }

    pub fn encrypt_to(
        &self,
        receiver: &Keyring,
        flags: u8,
        plaintext: &[u8],
    ) -> Result<EncryptedPackage, CryptoError> {
        Keyring::encrypt(self, receiver, flags, plaintext)
    }

    pub fn decrypt_from(
        &self,
        sender: &Keyring,
        flags: u8,
        package: &EncryptedPackage,
    ) -> Result<Vec<u8>, CryptoError> {
        Keyring::decrypt(self, sender, flags, package)
    }


    pub fn sign(&self, flags: u8, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.is_empty() {
            return Err(CryptoError::new_error_invalid_input("Empty data provided for signing"));
        }

        match flags {
            ALGORITHM_ECDSA => self.ec_keypair.sign(data),
            ALGORITHM_RSA => self.rsa_keypair.sign(data),
            _ => Err(CryptoError::new_error_signing("Invalid signature algorithm flag")),
        }
    }

    pub fn verify(&self, flags: u8, data: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
        if data.is_empty() || signature.is_empty() {
            return Err(CryptoError::new_error_invalid_input("Empty data or signature provided for verification"));
        }

        match flags {
            ALGORITHM_ECDSA => self.ec_keypair.verify(data, signature),
            ALGORITHM_RSA => self.rsa_keypair.verify(data, signature),
            _ => Err(CryptoError::new_error_verification("Invalid signature algorithm flag")),
        }
    }


    pub fn write_to_disk(&self, folder: &std::path::Path) -> bool {
        let keyring_path = folder.join("key.ring");

        let mut stream = serialize::DataStream::new(serialize::SER_DISK, serialize::VERSION);
        stream.stream_in(self); 
        let serialized_data = stream.data; 

        let mut file = match File::create(&keyring_path) {
            Ok(file) => file,
            Err(_) => return false,
        };
        if file.write_all(&serialized_data).is_err() {
            return false;
        }

        true
    }


    pub fn read_from_disk(folder: &std::path::Path) -> Result<Self, std::io::Error> {
        use std::fs::{self, File};
        use std::io::Write;
        use std::path::Path;
        use std::io::Read;

        let keyring_path = folder.join("key.ring");
        if !keyring_path.exists() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("key.ring file does not exist at '{}'", keyring_path.display()),
            ));
        }
        let mut file = File::open(&keyring_path)?;
        let mut serialized_data = Vec::new();
        file.read_to_end(&mut serialized_data)?;

        let mut stream = serialize::DataStream::new(serialize::SER_DISK, serialize::VERSION);
        stream.write(&serialized_data);
        let keyring = stream.stream_out::<Keyring>().map_err(|e| std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to deserialize key.ring: {}", e),
        ))?;
        Ok(keyring)
    }
}

macro_rules! impl_sign_for_keypair {
    ($struct_name:ident, $key_from_der:expr) => {
        impl $struct_name {
            pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
                let pkey = $key_from_der(&self.privkey).map_err(|e| {
                    CryptoError::new_error_invalid_key(&format!("Failed to load private key: {}", e))
                })?;
                let mut signer = Signer::new(MessageDigest::sha256(), &pkey)
                    .map_err(|e| CryptoError::new_error_signing(&format!("Failed to create signer: {}", e)))?;
                signer
                    .update(data)
                    .map_err(|e| CryptoError::new_error_signing(&format!("Failed to update signer: {}", e)))?;
                signer
                    .sign_to_vec()
                    .map_err(|e| CryptoError::new_error_signing(&format!("Failed to sign data: {}", e)))
            }
        }
    };
}

macro_rules! impl_verify_for_keypair {
    ($struct_name:ident, $key_from_der:expr) => {
        impl $struct_name {
            pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, CryptoError> {
                let pkey = $key_from_der(&self.pubkey).map_err(|e| {
                    CryptoError::new_error_invalid_key(&format!("Failed to load public key: {}", e))
                })?;
                let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)
                    .map_err(|e| CryptoError::new_error_verification(&format!("Failed to create verifier: {}", e)))?;
                verifier
                    .update(data)
                    .map_err(|e| CryptoError::new_error_verification(&format!("Failed to update verifier: {}", e)))?;
                verifier
                    .verify(signature)
                    .map_err(|e| CryptoError::new_error_verification(&format!("Failed to verify signature: {}", e)))
            }
        }
    };
}

serialize_derive::impl_serialize_for_struct! {
    target Keyring {
        readwrite(self.ec_keypair);
        readwrite(self.rsa_keypair);
    }
}

serialize_derive::impl_serialize_for_struct! {
    target EncryptedPackage {
        readwrite(self.encrypted_key);
        readwrite(self.ephemeral_pubkey);
        readwrite(self.iv);
        readwrite(self.ciphertext);
    }
}

macro_rules! impl_serialize_for_keypair {
    ($struct_name:ident) => {
        serialize_derive::impl_serialize_for_struct! {
            target $struct_name {
                if n_type & (serialize::SER_NETWORK | serialize::SER_GETHASH) != 0 {
                    readwrite(self.pubkey);
                }
                if n_type & serialize::SER_DISK != 0 {
                    readwrite(self.pubkey);
                    readwrite(self.privkey);
                }
            }
        }
    };
}

impl_sign_for_keypair!(
    EcKeyPair,
    |privkey: &[u8]| -> Result<PKey<Private>, ErrorStack> {
        let ec_key = openssl::ec::EcKey::private_key_from_der(privkey)?;
        PKey::from_ec_key(ec_key)
    }
);

impl_verify_for_keypair!(
    EcKeyPair,
    |pubkey: &[u8]| -> Result<PKey<Public>, ErrorStack> {
        let ec_key = openssl::ec::EcKey::public_key_from_der(pubkey)?;
        PKey::from_ec_key(ec_key)
    }
);

impl_sign_for_keypair!(
    RsaKeyPair,
    |privkey: &[u8]| -> Result<PKey<Private>, ErrorStack> {
        PKey::private_key_from_der(privkey)
    }
);

impl_verify_for_keypair!(
    RsaKeyPair,
    |pubkey: &[u8]| -> Result<PKey<Public>, ErrorStack> {
        PKey::public_key_from_der(pubkey)
    }
);

impl_serialize_for_keypair!(EcKeyPair);
impl_serialize_for_keypair!(RsaKeyPair);

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    #[test]
    fn ec_keypair_generation() {
        let keypair = EcKeyPair::new().expect("Failed to generate EC keypair");
        assert!(!keypair.pubkey.is_empty());
        assert!(!keypair.privkey.is_empty());
    }

    #[test]
    fn rsa_keypair_generation() {
        let keypair = RsaKeyPair::new().expect("Failed to generate RSA keypair");
        assert!(!keypair.pubkey.is_empty());
        assert!(!keypair.privkey.is_empty());
    }

    #[test]
    fn ec_sign_and_verify() {
        let keypair = EcKeyPair::new().unwrap();
        let data = b"hello ecdsa";
        let signature = keypair.sign(data).expect("ECDSA sign failed");
        assert!(keypair.verify(data, &signature).unwrap());
        assert!(!keypair.verify(b"other data", &signature).unwrap());
    }

    #[test]
    fn rsa_sign_and_verify() {
        let keypair = RsaKeyPair::new().unwrap();
        let data = b"hello rsa";
        let signature = keypair.sign(data).expect("RSA sign failed");
        assert!(keypair.verify(data, &signature).unwrap());
        assert!(!keypair.verify(b"other data", &signature).unwrap());
    }

    #[test]
    fn keyring_sign_and_verify() {
        let keyring = Keyring::new().unwrap();
        let data = b"sign me";

        let sig = keyring.sign(ALGORITHM_ECDSA, data).expect("ECDSA sign failed");
        let verified = keyring.verify(ALGORITHM_ECDSA, data, &sig).expect("ECDSA verify failed");
        assert!(verified);

        let sig = keyring.sign(ALGORITHM_RSA, data).expect("RSA sign failed");
        let verified = keyring.verify(ALGORITHM_RSA, data, &sig).expect("RSA verify failed");
        assert!(verified);

        assert!(keyring.sign(99, data).is_err());
        assert!(keyring.verify(99, data, &sig).is_err());
    }

    #[test]
    fn test_self_encrypt_decrypt() {
        let keyring = Keyring::new().expect("Failed to create keyring");
        let message = b"Self-encryption test";

        let package_rsa = Keyring::encrypt(&keyring, &keyring, ALGORITHM_RSA, message)
            .expect("RSA encryption failed");
        let decrypted_rsa = Keyring::decrypt(&keyring, &keyring, ALGORITHM_RSA, &package_rsa)
            .expect("RSA decryption failed");
        assert_eq!(decrypted_rsa, message);

        let package_ecdhe = Keyring::encrypt(&keyring, &keyring, ALGORITHM_ECDHE, message)
            .expect("ECDHE encryption failed");
        let decrypted_ecdhe = Keyring::decrypt(&keyring, &keyring, ALGORITHM_ECDHE, &package_ecdhe)
            .expect("ECDHE decryption failed");
        assert_eq!(decrypted_ecdhe, message);
    }

    #[test]
    fn test_rsa_encrypt_decrypt() {
        let alice_keyring = Keyring::new().expect("Failed to create Alice's keyring");
        let bob_keyring = Keyring::new().expect("Failed to create Bob's keyring");

        let alice_message = b"Hello, Bob! From Alice.";

        let package_rsa = Keyring::encrypt(
            &alice_keyring,
            &bob_keyring,
            ALGORITHM_RSA,
            alice_message,
        ).expect("Alice RSA encryption failed");

        let decrypted_rsa = Keyring::decrypt(
            &bob_keyring,
            &alice_keyring,
            ALGORITHM_RSA,
            &package_rsa,
        ).expect("Bob RSA decryption failed");

        assert_eq!(
            decrypted_rsa,
            alice_message,
            "Bob RSA decryption did not match original message"
        );
        assert_eq!(
            String::from_utf8_lossy(&decrypted_rsa),
            "Hello, Bob! From Alice.",
            "RSA decrypted message content mismatch"
        );
    }

    #[test]
    fn test_ecdhe_encrypt_decrypt() {
        let alice_keyring = Keyring::new().expect("Failed to create Alice's keyring");
        let bob_keyring = Keyring::new().expect("Failed to create Bob's keyring");

        let alice_message = b"Hello, Bob! From Alice.";

        let package_ecdhe = Keyring::encrypt(
            &alice_keyring,
            &bob_keyring,
            ALGORITHM_ECDHE,
            alice_message,
        ).expect("Alice ECDHE encryption failed");

        let decrypted_ecdhe = Keyring::decrypt(
            &bob_keyring,
            &alice_keyring,
            ALGORITHM_ECDHE,
            &package_ecdhe,
        ).expect("Bob ECDHE decryption failed");

        assert_eq!(
            decrypted_ecdhe,
            alice_message,
            "Bob ECDHE decryption did not match original message"
        );
        assert_eq!(
            String::from_utf8_lossy(&decrypted_ecdhe),
            "Hello, Bob! From Alice.",
            "ECDHE decrypted message content mismatch"
        );
    }

    #[test]
    fn keyring_encrypt_ecsa_should_fail() {
        let keyring = Keyring::new().unwrap();
        let plaintext = b"Secret message";
        let res = Keyring::encrypt(&keyring, &keyring, ALGORITHM_ECDSA, plaintext);
        assert!(res.is_err());
        assert!(matches!(res, Err(CryptoError::ErrorInvalidInput { .. })));
    }

    #[test]
    fn keyring_decrypt_ecdsa_should_fail() {
        let keyring = Keyring::new().unwrap();
        let package = EncryptedPackage {
            encrypted_key: vec![],
            ephemeral_pubkey: vec![],
            iv: vec![],
            ciphertext: vec![],
        };
        let res = Keyring::decrypt(&keyring, &keyring, ALGORITHM_ECDSA, &package);
        assert!(res.is_err());
        assert!(matches!(res, Err(CryptoError::ErrorInvalidInput { .. })));
    }

    #[test]
    fn fingerprint_generation() {
        let ec = EcKeyPair::new().unwrap();
        let rsa = RsaKeyPair::new().unwrap();

        let fp_ec = ec.fingerprint().expect("EC fingerprint failed");
        let fp_rsa = rsa.fingerprint().expect("RSA fingerprint failed");
        assert_eq!(fp_ec.len(), 32);
        assert_eq!(fp_rsa.len(), 32);
    }

    #[test]
    fn keyring_new_creates_keys() {
        let kr = Keyring::new().expect("Keyring creation failed");
        assert!(!kr.ec_keypair.pubkey.is_empty());
        assert!(!kr.ec_keypair.privkey.is_empty());
        assert!(!kr.rsa_keypair.pubkey.is_empty());
        assert!(!kr.rsa_keypair.privkey.is_empty());
    }

    #[test]
    fn rsa_encrypt_empty_data() {
        let keypair = RsaKeyPair::new().unwrap();
        let data = b"";
        let result = keypair.encrypt(data);
        assert!(matches!(result, Err(CryptoError::ErrorInvalidInput { .. })));
    }

    #[test]
    fn rsa_decrypt_invalid_data() {
        let keypair = RsaKeyPair::new().unwrap();
        let invalid_data = vec![0u8; 100];
        let result = keypair.decrypt(&invalid_data);
        assert!(matches!(result, Err(CryptoError::ErrorInvalidInput { .. })));
    }

    #[test]
    fn ecdhe_encrypt_decrypt_empty() {
        let keyring = Keyring::new().unwrap();
        let plaintext = b"";
        let result = Keyring::encrypt(&keyring, &keyring, ALGORITHM_ECDHE, plaintext);
        assert!(matches!(result, Err(CryptoError::ErrorInvalidInput { .. })));
    }

    #[test]
    fn ecdhe_decrypt_invalid_ephemeral_key() {
        let sender_keyring = Keyring::new().expect("Failed to create sender keyring");
        let receiver_keyring = Keyring::new().expect("Failed to create receiver keyring");

        let package = EncryptedPackage {
            encrypted_key: vec![],
            ephemeral_pubkey: vec![0u8; 100],
            iv: vec![0u8; 12],
            ciphertext: vec![0u8; 116],
        };

        let result = Keyring::decrypt(
            &receiver_keyring,
            &sender_keyring,
            ALGORITHM_ECDHE,
            &package,
        );

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(CryptoError::ErrorInvalidKey { .. })
        ));
    }


    #[test]
    fn test_encrypt_decrypt_to_from_rsa() {
        let alice = Keyring::new().expect("Failed to create Alice's keyring");
        let bob = Keyring::new().expect("Failed to create Bob's keyring");
        let message = b"Hello Bob, RSA!";

        let package = alice
            .encrypt_to(&bob, ALGORITHM_RSA, message)
            .expect("RSA encryption failed");
        let decrypted = bob
            .decrypt_from(&alice, ALGORITHM_RSA, &package)
            .expect("RSA decryption failed");

        assert_eq!(decrypted, message, "RSA decrypted message mismatch");
    }

    #[test]
    fn test_encrypt_decrypt_to_from_ecdhe() {
        let alice = Keyring::new().expect("Failed to create Alice's keyring");
        let bob = Keyring::new().expect("Failed to create Bob's keyring");
        let message = b"Hello Bob, ECDHE!";

        let package = alice
            .encrypt_to(&bob, ALGORITHM_ECDHE, message)
            .expect("ECDHE encryption failed");
        let decrypted = bob
            .decrypt_from(&alice, ALGORITHM_ECDHE, &package)
            .expect("ECDHE decryption failed");

        assert_eq!(decrypted, message, "ECDHE decrypted message mismatch");
    }

    #[test]
    fn test_encrypt_to_invalid_algorithm() {
        let alice = Keyring::new().unwrap();
        let bob = Keyring::new().unwrap();
        let message = b"Invalid test";

        let res = alice.encrypt_to(&bob, 99, message);
        assert!(res.is_err());
    }

    #[test]
    fn test_decrypt_from_invalid_algorithm() {
        let keyring = Keyring::new().unwrap();
        let package = EncryptedPackage {
            encrypted_key: vec![],
            ephemeral_pubkey: vec![],
            iv: vec![],
            ciphertext: vec![],
        };

        let res = keyring.decrypt_from(&keyring, 99, &package);
        assert!(res.is_err());
    }


    #[test]
    fn keyring_write_read_disk() {
        let temp_dir = TempDir::new().expect("Failed to create temporary directory");
        let folder = temp_dir.path();

        let original_keyring = Keyring::new().expect("Failed to create keyring");

        let write_success = original_keyring.write_to_disk(folder);
        assert!(write_success, "Failed to write keyring to disk");

        let read_keyring = Keyring::read_from_disk(folder).expect("Failed to read keyring from disk");

        assert_eq!(
            original_keyring.ec_keypair, read_keyring.ec_keypair,
            "EC keypair mismatch after read from disk"
        );
        assert_eq!(
            original_keyring.rsa_keypair, read_keyring.rsa_keypair,
            "RSA keypair mismatch after read from disk"
        );
    }
}