# `serialize`


**`serialize`** is a lightweight serialization framework that provides the **`DataStream`** type a unified, in-memory byte buffer designed for efficient binary I/O. It offers a cursor-based interface for **reading, writing, seeking, and modifying data**,  
while automatically tracking progress behind the scenes. At its core, `serialize` makes it simple to move between structured Rust values and raw bytes   through a consistent and extensible API.

---

## Core Concepts

### `DataStream`
A cursor-based byte buffer built on top of `Vec<u8>` with support for:

- **Reading & Writing** – push and pull raw or structured values  
- **Seeking** – move the cursor forward or backward  
- **In-place Modification** – insert or erase data at any position  
- **Inspection** – check buffer state and cursor position  

### Serialization Traits
Implement or derive `Serialize` and `Deserialize` for your own types.  
These traits make the framework **flexible and extensible**, covering:

- **Primitives**: `u8`, `i32`, `bool`, etc.  
- **Collections**: `String`, `Vec<T>`  
- **Tuples**: `(T,)`, `(K, V)`  
- **Fixed-size arrays**: `[u8; 4]`, `[u8; 32]`, …  
- **Unit type**: `()`  
- **Custom types**: [`serialize_derive`](./serialize_derive/README.md)

---

## Core Methods

- `stream_in(&value)` – Serialize a value into the buffer  
- `stream_out::<T>()` – Deserialize a value of type `T` from the buffer  

---


---
### Basic Writing and Reading Bytes

```rust
let mut s = DataStream::default();
// Write raw bytes
s.write(b"Rust");
assert_eq!(s.to_string(), "Rust");


// Read bytes into a buffer
let mut buf = [0u8; 2];
s.read(&mut buf).unwrap();
assert_eq!(&buf, b"Ru");

// Cursor moves forward after read
assert_eq!(s.cursor, 2);
}
```

Quickstart Example
```rust

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut buf = DataStream::default();

    // Primitives
    buf.stream_in(&123u8)?;
    buf.stream_in(&true)?;


    // Collection
    let list = vec![10u16, 20, 30];
    buf.stream_in(&list)?;

    // Custom types → see `serialize_derive`

    assert_eq!(buf.stream_out::<u8>()?, 123);
    assert_eq!(buf.stream_out::<bool>()?, true);
    assert_eq!(buf.stream_out::<Vec<u16>>()?, list);

    println!("Done!");
    Ok(())
}
```

## Detailed Examples

Primitives & Booleans
``` rust 
let mut s = DataStream::default();
// Insert values in sequence: u8, i8, u16, bool
s.stream_in(&0xFFu8)?;
s.stream_in(&-1i8)?;
s.stream_in(&65535u16)?;
s.stream_in(&true)?;

// Read back in the same order
assert_eq!(s.stream_out::<u8>()?, 0xFF);
assert_eq!(s.stream_out::<i8>()?, -1);
assert_eq!(s.stream_out::<u16>()?, 65535);
assert_eq!(s.stream_out::<bool>()?, true);

```

### Strings & Vectors

```rust
let mut s = DataStream::default();
let text    = "Hello, World!".to_string();
let numbers = vec![1u32, 2, 3, 4];

// Serialize
s.stream_in(&text)?;
s.stream_in(&numbers)?;

// Deserialize
let deser_text: String = s.stream_out()?;      // stream out withot passing the type
let deser_numbers: Vec<u32> = s.stream_out()?; // strea mout withot passing the type
assert_eq!(deser_text, text);
assert_eq!(deser_numbers, numbers);
```

### Fixed‑Size Arrays

```rust
let mut s = DataStream::default();
let arr4  = [1u8, 2, 3, 4];
let arr32 = [0xAAu8; 32];

// Serialize
s.stream_in(&arr4)?;
s.stream_in(&arr32)?;

// Deserialize and verify
let deser_arr4: [u8; 4] = s.stream_out()?;  // stream out withot passing the type
let deser_arr32: [u8; 32] = s.stream_out()?; // strea mout withot passing the type
assert_eq!(deser_arr4, arr4);
assert_eq!(deser_arr32, arr32);
```
