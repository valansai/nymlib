# serialize_derive

**`serialize_derive`** is a procedural macro crate for the [`serialize`](./serialize) framework.  
It provides a custom macro for automatically implementing the `Serialize` trait on your structs, inspired by Bitcoin’s serialization format.

This crate is not meant to be used directly by end-users. Instead, it is typically re-exported by [`serialize`](./serialize).

---

##  Features

- Declarative syntax for describing how a struct should be serialized/deserialized.  
- Inspired by Bitcoin Core’s serialization style.  
- Supports:
  - `readwrite` statements for reading/writing fields
  - Assignments (`a = b;`)
  - Conditional blocks (`if ... { ... } else { ... }`)
- Automatically generates:
  - `get_serialize_size`
  - `serialize`
  - `unserialize`

---

##  Example

Suppose you have a struct that implements the `Serialize` trait using the macro:

```rust
use nymlib::serialize::{Serialize, DataStream};
use nymlib::serialize_derive::impl_serialize_for_struct;
use std::io::Write;

#[derive(PartialEq, Debug, Default)]
struct MyMessage {
    version: u32,
    payload: Vec<u8>,
}

impl_serialize_for_struct! {
    target MyMessage {
        readwrite(self.version);
        readwrite(self.payload);
    }
}

fn main() {
    let message = MyMessage {
        version: 1,
        payload: b"hello".to_vec(),
    };

    // Serialize into a DataStream
    let mut stream = DataStream::default();
    stream.stream_in(&message);

    // Get the serialized bytes
    let serialized: Vec<u8> = stream.data.to_vec();

    // Simulate receiving the serialized bytes
    let mut recv_stream = DataStream::default();
    recv_stream.write(&serialized);

    // Deserialize back into MyMessage
    let msg_received = recv_stream.stream_out::<MyMessage>().unwrap();

    println!("Original:   {:?}", message);
    println!("Received:   {:?}", msg_received);

    assert_eq!(msg_received, message);
}

```

## 📖 Extended Example

The macro supports **conditional serialization**.  
This allows you to include or exclude certain fields depending on the serialization context (e.g. network transfer vs local storage).

```rust
use nymlib::serialize::{Serialize, DataStream, SER_NETWORK, SER_DISK, VERSION};
use nymlib::serialize_derive::impl_serialize_for_struct;
use std::io::Write;

#[derive(Debug, Default, PartialEq)]
struct MyMessage {
    version: u32,
    payload: Vec<u8>,
    privkey: Vec<u8>,
}

impl_serialize_for_struct! {
    target MyMessage {
        readwrite(self.version);
        readwrite(self.payload);

        // Conditionally serialize the private key:
        if (n_type & (SER_NETWORK)) == 0 {
            readwrite(self.privkey);
        }
    }
}

fn main() {
    let message = MyMessage {
        version: 1,
        payload: b"hello nym".to_vec(),
        privkey: b"secretekey".to_vec(),
    };

    // Serialize for network transfer (private key NOT included)
    let mut network_stream = DataStream::new(SER_NETWORK, VERSION);
    network_stream.stream_in(&message);
    let network_bytes = network_stream.data.to_vec(); // get Vec<u8>

    // Serialize for disk storage (private key included)
    let mut disk_stream = DataStream::new(SER_DISK, VERSION);
    disk_stream.stream_in(&message);
    let disk_bytes = disk_stream.data.to_vec();

    // Deserialize network message
    let mut network_stream_received = DataStream::new(SER_NETWORK, VERSION);
    network_stream_received.write(&network_bytes);
    let deserialized_network = network_stream_received.stream_out::<MyMessage>().unwrap();

    assert_eq!(deserialized_network.privkey, Vec::<u8>::new()); // privkey is empty
    println!("Deserialized network message: {:?}", deserialized_network);

    // Deserialize disk message
    let mut disk_stream_received = DataStream::new(SER_DISK, VERSION);
    disk_stream_received.write(&disk_bytes);
    let deserialized_disk = disk_stream_received.stream_out::<MyMessage>().unwrap();

    assert_eq!(deserialized_disk.privkey, message.privkey); // privkey preserved
    println!("Deserialized disk message: {:?}", deserialized_disk);

    println!("Network buffer: {:?}", network_bytes);
    println!("Disk buffer: {:?}", disk_bytes);
}


```

## Macro Syntax
- ``` target StructName { ... }```
   Declares which struct to implement serialization for.

- ``` readwrite(this.field);```  Serializes or deserializes the given field.
- ``` field_a = field_b;``` Assignment within serialization/deserialization logic.
- ``` if condition { ... } else { ... }```  Conditional serialization logic.

The macro expands to an implementation of Serialize:

``` rust 
impl Serialize for MyMessage {
    fn get_serialize_size(&self, n_type: i32, n_version: i32) -> usize { /* ... */ }
    fn serialize<W: std::io::Write>(&self, writer: &mut W, n_type: i32, n_version: i32) -> std::io::Result<()> { /* ... */ }
    fn unserialize<R: std::io::Read>(&mut self, reader: &mut R, n_type: i32, n_version: i32) -> std::io::Result<()> { /* ... */ }
}
```


