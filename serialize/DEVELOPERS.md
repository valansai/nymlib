
## Overview

This library provides a Rust implementation for serializing and deserializing data, supporting various data types and use cases (disk storage, network transmission, and hashing). Key features include:

- **Serialize Trait**: Defines methods for computing serialization size, serializing, and deserializing data, with support for different serialization contexts (`SER_DISK`, `SER_NETWORK`, `SER_GETHASH`).
- **Deserialize Trait**: Provides a default implementation for deserializing types that implement `Serialize` and `Default`.
- **GetHash Trait**: Generates a 32-byte SHA-256 hash of serialized data for types implementing `Serialize`.
- **DataStream**: A versatile struct for managing serialized data, supporting reading, writing, and manipulation of byte streams.
- **Utilities**: Includes functions for compact size encoding (`get_size_of_compact_size`, `write_compact_size`, `read_compact_size`) and macros for implementing serialization for basic types, arrays, tuples, and custom structs.

The library is designed for developers building applications that require efficient and flexible data serialization, such as cryptographic systems, network protocols, or persistent storage.

## Components

### Serialize Trait

The `Serialize` trait defines the interface for serializing and deserializing data. It supports different serialization contexts via `n_type` flags (`SER_DISK`, `SER_NETWORK`, `SER_GETHASH`) and a version number (`VERSION = 103`).

#### Available Methods for `Serialize`

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `get_serialize_size` | `&self, n_type: i32, n_version: i32` | `usize` | Returns the size of the serialized data in bytes for the given serialization type and version. |
| `serialize` | `&self, writer: &mut W, n_type: i32, n_version: i32` where `W: Write` | `Result<(), std::io::Error>` | Serializes the data to the provided writer, respecting the serialization type and version. |
| `unserialize` | `&mut self, reader: &mut R, n_type: i32, n_version: i32` where `R: Read` | `Result<(), std::io::Error>` | Deserializes data from the provided reader into `self`, respecting the serialization type and version. |
| `to_datastream` | `&self, n_type: i32, n_version: i32` | `Result<DataStream, std::io::Error>` | Serializes the data into a new `DataStream` with the specified type and version. |

#### Implementations
- Basic types (`u8`, `u16`, `u32`, `u64`, `u128`, `i8`, `i16`, `i32`, `i64`, `i128`, `f32`, `f64`, `bool`, `char`): Serialize to/from little-endian bytes.
- `String` and `&str`: Use compact size encoding for length, followed by UTF-8 bytes.
- `Vec<T>`: Serialize length as compact size, followed by serialized elements.
- Arrays (`[T; N]` for specific sizes): Serialize elements sequentially.
- Tuples (up to 6 elements): Serialize each component sequentially.
- `DataStream`: Serializes its internal `data` vector with compact size encoding.
- Custom structs (via `impl_serialize_for_struct!`): Configurable serialization for fields, with conditional inclusion based on `n_type`.

### Deserialize Trait

The `Deserialize` trait provides a default implementation for types that implement `Serialize` and `Default`, allowing deserialization into a new instance.

#### Available Methods for `Deserialize`

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `deserialize` | `reader: &mut R, n_type: i32, n_version: i32` where `R: Read` | `Result<Self, std::io::Error>` | Deserializes data from the provided reader into a new instance, using the type and version. |

### GetHash Trait

The `GetHash` trait generates a 32-byte SHA-256 hash of serialized data for types implementing `Serialize`.

#### Available Methods for `GetHash`

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `get_hash` | `&self` | `[u8; 32]` | Serializes the data with `SER_GETHASH | SER_DISK` and computes a SHA-256 hash. |

### DataStream

The `DataStream` struct manages a byte stream for serialization and deserialization, with fields for data storage, read/write positions, and serialization context. It implements `Read`, `Write`, and `Serialize` traits for flexible data handling.

#### Available Methods for `DataStream`

| Method | Parameters | Return Type | Description |
|--------|------------|-------------|-------------|
| `new` | `n_type: i32, n_version: i32` | `Self` | Creates a new `DataStream` with the specified serialization type and version. |
| `write_data` | `&mut self, s: &[u8]` | `()` | Appends the provided bytes to the stream, seeking to the end. |
| `extend_from_datastream` | `&mut self, other: &DataStream` | `()` | Appends another `DataStream`'s data to this stream. |
| `copy` | `&self` | `DataStream` | Creates a new `DataStream` with copied data and same context. |
| `read_value` | `&mut self` | `Result<T, std::io::Error>` where `T: Serialize + Default` | Reads and deserializes a value of type `T` from the stream. |
| `begin_index` | `&self` | `usize` | Returns the current read position. |
| `end_index` | `&self` | `usize` | Returns the total data length. |
| `erase` | `&mut self, start: usize, end: Option<usize>` | `()` | Removes data from `start` to `end` (or end of data). |
| `compact` | `&mut self` | `()` | Removes data before the read position, resetting `read_pos`. |
| `unread_str` | `&self` | `&[u8]` | Returns a slice of unread data from the current cursor. |
| `rewind` | `&mut self, n: usize` | `bool` | Moves the read position back by `n` bytes if possible. |
| `ignore` | `&mut self, n_size: usize` | `&mut Self` | Advances the read position by `n_size` bytes, clearing data if at end. |
| `raw_write` | `&mut self, s: &[u8], pos: usize` | `()` | Writes bytes at the specified position, preserving cursor. |
| `raw_read_buf` | `&self, start: usize, size: usize` | `&[u8]` | Returns a slice of data from `start` with length `size`. |
| `seek` | `&mut self, position: u64` | `()` | Sets the cursor to the specified position. |
| `seek_to_end` | `&mut self` | `()` | Sets the cursor to the end of the data. |
| `size` | `&self` | `usize` | Returns the total data length. |
| `empty` | `&self` | `bool` | Returns `true` if the data is empty. |
| `to_bytes` | `&self` | `Vec<u8>` | Returns a copy of the data as a `Vec<u8>`. |
| `to_hex` | `&self` | `String` | Converts the data to a hexadecimal string. |
| `to_string` | `&self` | `String` | Converts unread data to a UTF-8 string (lossy). |
| `write_obj` | `&mut self, obj: &T` where `T: Serialize + ?Sized` | `Result<(), std::io::Error>` | Serializes an object into the stream. |
| `read_obj` | `&mut self, obj: &mut T` where `T: Serialize` | `Result<(), std::io::Error>` | Deserializes an object from the stream into `obj`. |
| `stream_in` | `&mut self, obj: &T` where `T: Serialize + ?Sized` | `Result<(), std::io::Error>` | Alias for `write_obj`. |
| `stream_out` | `&mut self` where `T: Serialize + Default` | `Result<T, std::io::Error>` | Alias for `read_value`. |

#### Implementations
- `Read`: Reads data from the stream, updating `read_pos` and handling partial reads.
- `Write`: Appends data to the stream.
- `From<Vec<u8>>`: Creates a `DataStream` from a byte vector.
- `Shl` and `Shr`: Operator overloads for convenient serialization (`<<`) and deserialization (`>>`).

### Serialization Utilities

#### Compact Size Functions

| Function | Parameters | Return Type | Description |
|----------|------------|-------------|-------------|
| `get_size_of_compact_size` | `n_size: u64` | `usize` | Returns the size of the compact size encoding for the given length (1, 3, 5, or 9 bytes). |
| `write_compact_size` | `writer: &mut W, n_size: u64` where `W: Write` | `Result<(), std::io::Error>` | Writes a compact size encoding to the writer (1 byte for <253, 3 for ≤u16::MAX, 5 for ≤u32::MAX, 9 for larger). |
| `read_compact_size` | `reader: &mut R` where `R: Read` | `Result<u64, std::io::Error>` | Reads a compact size encoding from the reader, returning the decoded length. |

#### Macros

| Macro | Description |
|-------|-------------|
| `impl_serialize_for_basic_types!` | Implements `Serialize` for basic numeric types, using little-endian encoding. |
| `impl_serialize_for_array!` | Implements `Serialize` for fixed-size arrays of specific lengths (1, 2, 4, 8, 12, 16, 32, 64, 128, 256). |
| `impl_serialize_for_tuples!` | Implements `Serialize` for tuples with 1 to 6 elements. |
| `impl_serialize_from_string!` | Implements `Serialize` for types with a string representation and a parsing function. |
| `impl_serialize_for_struct!` | Implements `Serialize` for custom structs, allowing conditional field serialization based on `n_type`. |

### Example Structs
```rust
[derive(Default, Clone)]
struct InnerStruct {
    flag: u8,
    data: u64,
}

impl_serialize_for_struct! {
    target InnerStruct {
        readwrite(self.flag);
        if (n_type & (SER_NETWORK | SER_GETHASH)) == 0 {
            readwrite(self.data);
        }
    }
}


#[derive(Default, Clone)]
struct ExampleStruct {
    id: i32,
    name: String,
    inner: InnerStruct,
    values: Vec<u64>,
}

impl_serialize_for_struct! {
    target ExampleStruct {
        readwrite(self.id);
        readwrite(self.name);
        readwrite(self.inner);
        if (n_type & (SER_NETWORK | SER_GETHASH)) == 0 {
            readwrite(self.values);
        }
    }
}

```
#### InnerStruct

| Field | Type | Description |
|-------|------|-------------|
| `flag` | `u8` | A single-byte flag, always serialized. |
| `data` | `u64` | A 64-bit value, serialized only for non-network, non-hashing contexts. |

#### ExampleStruct

| Field | Type | Description |
|-------|------|-------------|
| `id` | `i32` | A 32-bit identifier, always serialized. |
| `name` | `String` | A string, serialized with compact size encoding. |
| `inner` | `InnerStruct` | A nested struct, serialized as defined. |
| `values` | `Vec<u64>` | A vector of 64-bit values, serialized only for non-network, non-hashing contexts. |
