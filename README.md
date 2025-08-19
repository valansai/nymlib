# nymlib

**nymlib** is a Rust workspace providing a collection of foundational libraries for secure, efficient, and ergonomic networking and cryptographic development.  It consists of multiple crates that can be used independently or together, with `nymlib` serving as a unifying export layer.

---

## Workspace Structure

This workspace contains the following libraries:
- `nymsocket`: A high level socket like abstraction of `nymsdk`
- `crypto`: A cryptographic library for key generation, encryption, decryption, signing, and verification using ECDSA, RSA, and ECDHE algorithms.
- `serialize`: A flexible serialization framework like Bitcoins for encoding and decoding data structures with support for compact size encoding and hash generation.
- `serialize_derive`: A procedural macro crate for generating serialization and deserialization code for structs



## Features
- Flexible usage of ```nymsdk``` client in highlevel abstraction
- Cryptographic Primitives: Secure key generation, encryption/decryption (RSA, ECDHE), and signing/verification (ECDSA, RSA).
- Flexible Serialization: Compact and efficient serialization/deserialization with conditional field handling and support for various data types.
- Extensible Design: Modular crates that can be used independently or combined for complex applications.
- Test Suite: Each lib contains extensive unit tests. 

### Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
nymlib = { git = "https://github.com/valansai/nymlib", branch = "main" }
```

## 📖 Examples & Usage

Each crate in this workspace comes with its own README that includes examples, usage notes, and API details.  
If you’re looking for how to use a specific library, check out its documentation:

- [`nymsocket`](./nymsocket/README.md) — High-level socket interface for the Nym mixnet  
- [`serialize`](./serialize/README.md) — Serialization framework  
- [`serialize_derive`](./serialize_derive/README.md) — Derive macros for serialization  
- [`crypto`](./crypto/README.md) — Cryptographic primitives  
- [`nymlib`](./nymlib/README.md) — Aggregator crate that re-exports everything
---



Nym address: n1cf9fy9wvcp04wdf993qw2fre606ujlxye0yry4
