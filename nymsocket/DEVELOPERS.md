# Developers Guide

This guide is for developers working with the Nym mixnet-based socket library, which provides tools for anonymous and individual communication over the Nym network. The library includes the `SockAddr`, `SocketMessage`, `Client`, and `Socket` types, built in Rust with dependencies on `nym_sdk`, `tokio`, `clap`, and a custom `serialize` module. Below, you'll find an overview, detailed component descriptions, method tables, usage examples, and contribution guidelines.


## Overview

This library provides a Rust implementation for communicating over the Nym mixnet, a privacy-focused network for anonymous and secure messaging. Key features include:

- **SockAddr**: An enum representing mixnet addresses (`NymAddress` for individual recipients, `SenderTag` for anonymous reply tags, and `Null` for invalid/placeholder addresses).
- **SocketMessage**: A struct for messages, including sender address, data, and timestamp, with serialization support.
- **Client**: An enum with `StandardClient` (persistent storage) and `EphemeralClient` (in-memory) variants for managing mixnet connections.
- **Socket**: The main interface for sending and receiving messages, supporting `Anonymous`, `Individual`, and `Null` modes, with features like message filtering and muting.

The library is designed for developers building privacy-preserving applications, with a focus on modularity and thread-safety using `tokio` and `Arc<Mutex<...>>`.

## Components

### SockAddr

The `SockAddr` enum represents addresses in the Nym mixnet. It supports three variants:
- `NymAddress(Recipient)`: For individual recipients, identified by a Nym address.
- `SenderTag(AnonymousSenderTag)`: For anonymous reply tags, used for reply messages.
- `Null`: A placeholder for invalid or uninitialized addresses.

It implements the `Serialize` trait for network transmission, `From` for conversions from `Recipient`, `AnonymousSenderTag`, and strings, and `ToString` for string representations. The `GetHash` trait provides a 32-byte hash for address identification.

#### Available Methods for `SockAddr`

| Method/Trait | Parameters | Return Type | Description |
|--------------|------------|-------------|-------------|
| `is_individual` | `&self` | `bool` | Returns `true` if the `SockAddr` is a `NymAddress` variant (individual address), `false` otherwise. |
| `is_anonymous` | `&self` | `bool` | Returns `true` if the `SockAddr` is a `SenderTag` variant (anonymous address), `false` otherwise. |
| `is_null` | `&self` | `bool` | Returns `true` if the `SockAddr` is a `Null` variant, `false` otherwise. |
| `Default::default` | `()` | `SockAddr` | Returns a `SockAddr::Null` instance as the default value for the enum. |
| `Serialize::get_serialize_size` | `&self, _n_type: i32, _n_version: i32` | `usize` | Returns the size of the serialized `SockAddr` in bytes. For `Null`, returns the size of a single byte (type indicator). For `NymAddress` or `SenderTag`, includes the type byte, compact size of the string, and the string length. |
| `Serialize::serialize` | `&self, writer: &mut W, _n_type: i32, _n_version: i32` where `W: Write` | `Result<(), std::io::Error>` | Serializes the `SockAddr` to a writer. Writes a type byte (`0` for `Null`, `1` for `SenderTag`, `2` for `NymAddress`) followed by the compact size and string representation for non-`Null` variants. |
| `Serialize::unserialize` | `&mut self, reader: &mut R, _n_type: i32, _n_version: i32` where `R: Read` | `Result<(), std::io::Error>` | Deserializes a `SockAddr` from a reader. Reads the type byte and, for `NymAddress` or `SenderTag`, the compact size and string, converting them to the appropriate type. Sets `self` to `Null` for invalid type bytes. |
| `From<Recipient>` | `recipient: Recipient` | `SockAddr` | Converts a `Recipient` into a `SockAddr::NymAddress` variant. |
| `From<AnonymousSenderTag>` | `tag: AnonymousSenderTag` | `SockAddr` | Converts an `AnonymousSenderTag` into a `SockAddr::SenderTag` variant. |
| `From<&str>` | `s: &str` | `SockAddr` | Attempts to convert a string into a `SockAddr::NymAddress` by parsing it as a `Recipient`. Returns `SockAddr::Null` if parsing fails. |
| `ToString::to_string` | `&self` | `String` | Converts the `SockAddr` to its string representation. Returns the string form of the `Recipient` for `NymAddress`, the `AnonymousSenderTag` for `SenderTag`, or `"null"` for `Null`. |
| `GetHash::get_hash` | `&self` | `[u8; 32]` | Returns a 32-byte hash of the `SockAddr`'s string representation, used for identifying addresses (e.g., in muted address lists). |

### SocketMessage

The `SocketMessage` struct represents a message sent or received over the mixnet, containing:
- `from: SockAddr`: The sender's address.
- `data: Vec<u8>`: The message payload.
- `time: u64`: A timestamp (Unix epoch seconds) for staleness checking.

It implements the `Serialize` trait for network transmission and provides methods to check the sender type and message age.

#### Available Methods for `SocketMessage`

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `new` | `from: SockAddr, data: Vec<u8>` | `Self` | Creates a new `SocketMessage` with the given sender address and data, setting the timestamp to the current Unix epoch time. |
| `is_from_individual` | `&self` | `bool` | Returns `true` if the message's `from` field is a `SockAddr::NymAddress`, `false` otherwise. |
| `is_from_anonymous` | `&self` | `bool` | Returns `true` if the message's `from` field is a `SockAddr::SenderTag`, `false` otherwise. |
| `is_from_null` | `&self` | `bool` | Returns `true` if the message's `from` field is a `SockAddr::Null`, `false` otherwise. |
| `is_older_than` | `&self, threshold_secs: u64` | `bool` | Returns `true` if the message's age (current time minus timestamp) exceeds `threshold_secs`, `false` otherwise. |

### Client

The `Client` enum wraps two variants for managing mixnet connections:
- `StandardClient`: Uses persistent storage for configuration and keys.
- `EphemeralClient`: Operates in-memory without persistent storage.

Both variants wrap a `MixnetClient` from `nym_sdk` in an `Arc<Mutex<Option<MixnetClient>>>` for thread-safe access.

#### Available Methods for `Client`

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `StandardClient::new` | `client_path: &str` | `Option<Self>` | Creates a new `StandardClient` with a persistent configuration directory at `client_path`. Initializes storage paths and connects to the Nym mixnet. Returns `None` if initialization or connection fails. |
| `StandardClient::new_with_gateway` | `client_path: &str, gateway: &str` | `Option<Self>` | Creates a new `StandardClient` with a persistent configuration directory at `client_path` and connects to the specified `gateway` (Nym gateway ID). Returns `None` if initialization or connection fails. |
| `EphemeralClient::new` | `()` | `Option<Self>` | Creates a new `EphemeralClient` with no persistent storage (in-memory). Connects to the Nym mixnet. Returns `None` if initialization or connection fails. |
| `EphemeralClient::new_with_gateway` | `gateway: &str` | `Option<Self>` | Creates a new `EphemeralClient` and connects to the specified `gateway` (Nym gateway ID). Returns `None` if initialization or connection fails. |
| `getaddr` | `&self` | `Option<Recipient>` | Returns the `Recipient` address of the underlying mixnet client, if available. |
| `getsockaddr` | `&self` | `Option<SockAddr>` | Returns the `SockAddr` representation of the underlying mixnet client's address (as a `NymAddress`), if available. |
| `disconnect` | `&self` | `()` | Disconnects the underlying mixnet client, closing the connection to the Nym mixnet. |

### Socket

The `Socket` struct is the main interface for sending and receiving messages over the Nym mixnet. It supports three modes (`SocketMode`):
- `Anonymous`: Hides the sender's identity using SURBs (Single Use Reply Blocks).
- `Individual`: Exposes the sender's Nym address.
- `Null`: Disables sending (used as a placeholder).

It includes features like message filtering (staleness, muted addresses), metrics tracking, and thread-safe message reception.

#### Available Methods for `Socket`

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `new_standard` | `client_path: &str, mode: SocketMode` | `Option<Self>` | Creates a new `Socket` instance with a standard client using a persistent configuration directory specified by `client_path`. The `mode` determines whether the socket operates in `Anonymous`, `Individual`, or `Null` mode. Returns `None` if client initialization fails. |
| `new_standard_with_gateway` | `client_path: &str, gateway: &str, mode: SocketMode` | `Option<Self>` | Creates a new `Socket` instance with a standard client using a persistent configuration directory at `client_path` and the specified `gateway` (Nym gateway ID). The `mode` determines the communication mode. Returns `None` if client initialization fails. |
| `new_ephemeral` | `mode: SocketMode` | `Option<Self>` | Creates a new `Socket` instance with an ephemeral client (no persistent storage). The `mode` determines the communication mode. Returns `None` if client initialization fails. |
| `new_ephemeral_with_gateway` | `gateway: &str, mode: SocketMode` | `Option<Self>` | Creates a new `Socket` instance with an ephemeral client and the specified `gateway` (Nym gateway ID). The `mode` determines the communication mode. Returns `None` if client initialization fails. |
| `mute_address` | `address: impl Into<SockAddr>, duration_secs: u64` | `()` | Mutes messages from the specified `address` for `duration_secs` seconds by adding it to the muted addresses list. The address is hashed for storage. |
| `unmute_address` | `address: impl Into<SockAddr>` | `()` | Removes the specified `address` from the muted addresses list, allowing messages from it to be received again. |
| `listen` | `&mut self` | `()` | Listens for incoming messages on the mixnet. Filters out stale messages (if `check_stale` is enabled) and messages from muted addresses. Stores received messages in the `recv` vector. Stops when a stop signal is received. |
| `send` | `&mut self, data: Vec<u8>, to: impl Into<To>` | `bool` | Sends a `SocketMessage` containing `data` to the specified recipient (`to`). The message is serialized and sent based on the socket's mode (`Anonymous`, `Individual`, or `Null`). Returns `true` if the message is sent successfully, `false` otherwise. |
| `disconnect` | `&self` | `()` | Disconnects the underlying mixnet client and sends a stop signal to the listener, if active. |
| `getaddr` | `&self` | `Option<Recipient>` | Returns the `Recipient` address of the underlying mixnet client, if available. |
| `getsockaddr` | `&self` | `Option<SockAddr>` | Returns the `SockAddr` representation of the underlying mixnet client's address, if available. |

