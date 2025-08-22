# crypto

**`crypto`** is cryptographic library for managing key pairs (ECDSA and RSA), digital signatures, and hybrid encryption/decryption operations, built with OpenSSL



### This library supports:
  - ECDSA (secp256k1 curve) for signing/verification.
  - RSA (3072-bit minimum) for signing/verification and encryption.
  - Hybrid encryption schemes: RSA + AES-256-GCM or ECDHE + AES-256-GCM.

---

##  Features
  - Keyring 
  - Key Generation: Generation of ECDSA and RSA key pairs.
  - Signing & Verification: SHA-256 based signing/verification for both ECDSA and RSA.
  - Encryption & Decryption:
     - RSA-based hybrid encryption (RSA encrypts AES key, AES-GCM encrypts data).
     - ECDHE-based ephemeral key exchange for forward secrecy (ECDH derives AES key, AES-GCM encrypts data).
  - Fingerprints: Compute SHA-256 hashes of public keys for identification.


## What is a keyring 
A Keyring is a core struct that serves as a secure container and manager for a pair of asymmetric cryptographic keys: an ECDSA key pair (using the secp256k1 elliptic curve) and an RSA key pair (with a minimum size of 3072 bits). It acts as a unified interface for performing common cryptographic operations, ensuring secure key handling,
  
  - Generation: Create new key pairs using Keyring::new(), which internally calls secure OpenSSL functions for randomness and key creation.
  - Signing and Verification: Use sign() and verify() with algorithm flags (e.g., ALGORITHM_ECDSA or ALGORITHM_RSA) to create or check SHA-256-based signatures on data.
  - Encryption and Decryption: Supports hybrid schemes via encrypt() and decrypt():
    - RSA Mode (ALGORITHM_RSA): Generates a random AES-256-GCM key, encrypts it with RSA, and uses AES to encrypt the plaintext (producing an EncryptedPackage with IV, ciphertext, and encrypted key).
    - ECDHE Mode (ALGORITHM_ECDHE): Uses ephemeral elliptic curve Diffie-Hellman for forward secrecy—generates a temporary EC key, derives a shared secret, hashes it to an AES key, and encrypts the data (including the ephemeral public key in the package).
  - Serialization: Supports custom serialization/deserialization for persistence (e.g., to disk or network), with flags to control what data is included (e.g., exclude private keys for network transmission).


 For more techincal details about crypto see [DEVELOPERS.md](./DEVELOPERS.md) 


## Usage
Generating a Keyring




```rust
use nymlib::crypto;
use nymlib::serialize::{Serialize, DataStream, SER_NETWORK, SER_DISK, VERSION};
use std::io::Write;


fn main() -> Result<(), crypto::CryptoError> {
    let keyring = crypto::Keyring::new()?;
    
    println!("ECDSA Public Key: {:?}", keyring.ec_keypair.pubkey);
    println!("RSA Public Key: {:?}", keyring.rsa_keypair.pubkey);

        
    // Serialize for network transfer (private keys NOT included only pubkeys)
    let mut network_stream = DataStream::new(SER_NETWORK, VERSION);
    network_stream.stream_in(&keyring);
    let network_bytes = network_stream.data.to_vec(); // get Vec<u8>

    // Serialize for disk storage (private key included)
    let mut disk_stream = DataStream::new(SER_DISK, VERSION);
    disk_stream.stream_in(&keyring);
    let disk_bytes = disk_stream.data.to_vec();


    // Deserialize network received keyring 
    let mut network_stream_received = DataStream::new(SER_NETWORK, VERSION);
    network_stream_received.write(&network_bytes);
    let deserialized_network = network_stream_received.stream_out::<crypto::Keyring>().unwrap();

    assert_eq!(deserialized_network.ec_keypair.pubkey, keyring.ec_keypair.pubkey);   // pubkey is included
    assert_eq!(deserialized_network.rsa_keypair.pubkey, keyring.rsa_keypair.pubkey); // pubkey is included
    assert_eq!(deserialized_network.ec_keypair.privkey, Vec::<u8>::new()); // privkey is empty
    assert_eq!(deserialized_network.rsa_keypair.privkey, Vec::<u8>::new()); // privkey is empty

    // Deserialize disk Keyring
    let mut disk_stream_loaded = DataStream::new(SER_DISK, VERSION);
    disk_stream_loaded.write(&disk_bytes);
    let deserialized_disk = disk_stream_loaded.stream_out::<crypto::Keyring>().unwrap();


    assert_eq!(deserialized_disk.ec_keypair.pubkey, keyring.ec_keypair.pubkey);     // pubkey is preserved
    assert_eq!(deserialized_disk.rsa_keypair.pubkey, keyring.rsa_keypair.pubkey);   // pubkey is preserved
    assert_eq!(deserialized_disk.ec_keypair.privkey, keyring.ec_keypair.privkey);   // privkey preserved
    assert_eq!(deserialized_disk.rsa_keypair.privkey, keyring.rsa_keypair.privkey); // privkey preserved

    

    Ok(())
}
```

Signing and Verifying (ECDSA)
```rust

let data = b"Hello, world!";
let signature = keyring.sign(crypto::ALGORITHM_ECDSA, data)?;
let is_valid = keyring.verify(crypto::ALGORITHM_ECDSA, data, &signature)?;
assert!(is_valid);

```

Signing and Verifying (RSA)
```rust
let data = b"Hello, world!";
let signature = keyring.sign(crypto::ALGORITHM_RSA, data)?;
let is_valid = keyring.verify(crypto::ALGORITHM_RSA, data, &signature)?;
assert!(is_valid);

```

Encryption and Decryption (RSA Hybrid)
```rust
let plaintext = b"Secret message";
let package = keyring.encrypt(crypto::ALGORITHM_RSA, plaintext)?;
let decrypted = keyring.decrypt(crypto::ALGORITHM_RSA, &package)?;
assert_eq!(decrypted, plaintext);
```

Encryption and Decryption (ECDHE Hybrid)
```rust
let plaintext = b"Secret message with forward secrecy";
let package = keyring.encrypt(crypto::ALGORITHM_ECDHE, plaintext)?;
let decrypted = keyring.decrypt(crypto::ALGORITHM_ECDHE, &package)?;
assert_eq!(decrypted, plaintext);
```




