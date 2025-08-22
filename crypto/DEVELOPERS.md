
## Overview

This library provides a Rust implementation for cryptographic operations, focusing on secure key management and data protection. Key features include:

- **CryptoError**: An enum for handling cryptographic errors, covering key generation, serialization, signing, verification, and OpenSSL-related issues.
- **EcKeyPair**: A struct for ECDSA key pairs (using the secp256k1 curve), supporting signing, verification, and fingerprint generation.
- **RsaKeyPair**: A struct for RSA key pairs (minimum 3072-bit), supporting encryption, decryption, signing, verification, and fingerprint generation.
- **EncryptedPackage**: A struct for encapsulating encrypted data, including encrypted keys, ephemeral public keys, initialization vectors (IVs), and ciphertext.
- **Keyring**: A struct combining `EcKeyPair` and `RsaKeyPair`, providing high-level encryption, decryption, signing, verification, and disk storage functionality.

The library uses the `openssl` crate for cryptographic primitives, `zeroize` for secure memory handling, and a custom `serialize` module for data serialization. It is designed for developers building secure applications requiring robust cryptographic operations.

## Components

### CryptoError

The `CryptoError` enum defines error types for cryptographic operations, ensuring detailed error handling. Variants include errors for key generation, serialization, signing, verification, invalid keys, invalid inputs, OpenSSL issues, and buffer overflows.

#### Available Methods for `CryptoError`

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `new_error_key_generation` | `msg: &str` | `Self` | Creates a `CryptoError::ErrorKeyGeneration` with the provided message. |
| `new_error_serialization` | `msg: &str` | `Self` | Creates a `CryptoError::ErrorSerialization` with the provided message. |
| `new_error_signing` | `msg: &str` | `Self` | Creates a `CryptoError::ErrorSigning` with the provided message. |
| `new_error_verification` | `msg: &str` | `Self` | Creates a `CryptoError::ErrorVerification` with the provided message. |
| `new_error_invalid_key` | `msg: &str` | `Self` | Creates a `CryptoError::ErrorInvalidKey` with the provided message. |
| `new_error_invalid_input` | `msg: &str` | `Self` | Creates a `CryptoError::ErrorInvalidInput` with the provided message. |
| `new_error_openssl` | `err: ErrorStack` | `Self` | Creates a `CryptoError::ErrorOpenSSL` with the provided OpenSSL error stack. |
| `new_error_buffer_overflow` | `msg: &str` | `Self` | Creates a `CryptoError::ErrorBufferOverflow` with the provided message. |

### EcKeyPair

The `EcKeyPair` struct represents an ECDSA key pair using the secp256k1 curve. It stores public and private keys as DER-encoded `Vec<u8>` and implements secure memory handling via `zeroize`.

#### Available Methods for `EcKeyPair`

| Method/Trait | Parameters | Return Type | Description |
|--------------|------------|-------------|-------------|
| `new` | `()` | `Result<Self, CryptoError>` | Generates a new ECDSA key pair using the secp256k1 curve. Returns an error if key generation or serialization fails. |
| `sign` | `&self, data: &[u8]` | `Result<Vec<u8>, CryptoError>` | Signs the provided data using ECDSA with SHA-256. Returns the signature or an error if signing fails. |
| `verify` | `&self, data: &[u8], signature: &[u8]` | `Result<bool, CryptoError>` | Verifies the signature for the given data using ECDSA with SHA-256. Returns `true` if valid, `false` otherwise, or an error if verification fails. |
| `fingerprint` | `&self` | `Result<[u8; 32], CryptoError>` | Generates a 32-byte hash of the public key using the `SerializeHash` trait. Returns an error if the public key is empty. |
| `Default::default` | `()` | `Self` | Returns an `EcKeyPair` with empty public and private keys. |
| `Drop::drop` | `&mut self` | `()` | Zeroizes the private key to prevent memory leaks. |
| `Serialize` | Varies | Varies | Serializes the key pair. For `SER_DISK`, includes both public and private keys; for `SER_NETWORK` or `SER_GETHASH`, includes only the public key. |

### RsaKeyPair

The `RsaKeyPair` struct represents an RSA key pair with a minimum key size of 3072 bits. It supports encryption and decryption using PKCS1 OAEP padding, as well as signing and verification.

#### Available Methods for `RsaKeyPair`

| Method/Trait | Parameters | Return Type | Description |
|--------------|------------|-------------|-------------|
| `new` | `()` | `Result<Self, CryptoError>` | Generates a new RSA key pair with at least 3072-bit keys. Returns an error if generation or serialization fails. |
| `encrypt` | `&self, data: &[u8]` | `Result<Vec<u8>, CryptoError>` | Encrypts the provided data using RSA with PKCS1 OAEP padding. Returns the ciphertext or an error if the data is empty or the key is invalid. |
| `decrypt` | `&self, encrypted_data: &[u8]` | `Result<Vec<u8>, CryptoError>` | Decrypts the provided ciphertext using RSA with PKCS1 OAEP padding. Returns the plaintext or an error if the data or key is invalid. |
| `sign` | `&self, data: &[u8]` | `Result<Vec<u8>, CryptoError>` | Signs the provided data using RSA with SHA-256. Returns the signature or an error if signing fails. |
| `verify` | `&self, data: &[u8], signature: &[u8]` | `Result<bool, CryptoError>` | Verifies the signature for the given data using RSA with SHA-256. Returns `true` if valid, `false` otherwise, or an error if verification fails. |
| `fingerprint` | `&self` | `Result<[u8; 32], CryptoError>` | Generates a 32-byte hash of the public key using the `SerializeHash` trait. Returns an error if the public key is empty. |
| `Default::default` | `()` | `Self` | Returns an `RsaKeyPair` with empty public and private keys. |
| `Drop::drop` | `&mut self` | `()` | Zeroizes the private key to prevent memory leaks. |
| `Serialize` | Varies | Varies | Serializes the key pair. For `SER_DISK`, includes both public and private keys; for `SER_NETWORK` or `SER_GETHASH`, includes only the public key. |

### EncryptedPackage

The `EncryptedPackage` struct encapsulates encrypted data, including the encrypted key (for RSA), ephemeral public key (for ECDHE), initialization vector (IV), and ciphertext with an authentication tag (for AES-GCM).

#### Available Methods for `EncryptedPackage`

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `has_ephemeral_pubkey` | `&self` | `bool` | Returns `true` if the `ephemeral_pubkey` field is non-empty and contains non-zero bytes, indicating its use in ECDHE encryption. |
| `Serialize` | Varies | Varies | Serializes the `EncryptedPackage`, including `encrypted_key`, `ephemeral_pubkey`, `iv`, and `ciphertext`. |

### Keyring

The `Keyring` struct combines `EcKeyPair` and `RsaKeyPair`, providing a unified interface for cryptographic operations. It supports RSA and ECDHE encryption, as well as ECDSA and RSA signing/verification. It also handles disk storage for key persistence.

#### Available Methods for `Keyring`

| Method/Trait | Parameters | Return Type | Description |
|--------------|------------|-------------|-------------|
| `new` | `()` | `Result<Self, CryptoError>` | Creates a new `Keyring` with freshly generated `EcKeyPair` and `RsaKeyPair`. Returns an error if key generation fails. |
| `encrypt` | `&self, flags: u8, plaintext: &[u8]` | `Result<EncryptedPackage, CryptoError>` | Encrypts the plaintext using the specified algorithm (`ALGORITHM_RSA` or `ALGORITHM_ECDHE`). For RSA, encrypts an AES key; for ECDHE, uses a shared secret. Returns an `EncryptedPackage` or an error if the input or algorithm is invalid. |
| `decrypt` | `&self, flags: u8, package: &EncryptedPackage` | `Result<Vec<u8>, CryptoError>` | Decrypts the provided `EncryptedPackage` using the specified algorithm (`ALGORITHM_RSA` or `ALGORITHM_ECDHE`). Returns the plaintext or an error if the package or algorithm is invalid. |
| `sign` | `&self, flags: u8, data: &[u8]` | `Result<Vec<u8>, CryptoError>` | Signs the data using the specified algorithm (`ALGORITHM_ECDSA` or `ALGORITHM_RSA`). Returns the signature or an error if the input or algorithm is invalid. |
| `verify` | `&self, flags: u8, data: &[u8], signature: &[u8]` | `Result<bool, CryptoError>` | Verifies the signature for the given data using the specified algorithm (`ALGORITHM_ECDSA` or `ALGORITHM_RSA`). Returns `true` if valid, `false` otherwise, or an error if the input or algorithm is invalid. |
| `write_to_disk` | `&self, folder: &std::path::Path` | `bool` | Serializes the `Keyring` and writes it to a `key.ring` file in the specified folder. Returns `true` on success, `false` on failure. |
| `read_from_disk` | `folder: &std::path::Path` | `Result<Self, std::io::Error>` | Reads and deserializes a `Keyring` from a `key.ring` file in the specified folder. Returns the `Keyring` or an error if the file is missing or deserialization fails. |
| `Default::default` | `()` | `Self` | Returns a `Keyring` with default (empty) `EcKeyPair` and `RsaKeyPair`. |
| `Drop::drop` | `&mut self` | `()` | Ensures proper cleanup (handled by `EcKeyPair` and `RsaKeyPair` drop implementations). |
| `Serialize` | Varies | Varies | Serializes the `Keyring`, including both `ec_keypair` and `rsa_keypair`. |

