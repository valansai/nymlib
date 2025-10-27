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

use serialize_derive::impl_serialize_for_struct;

pub const VERSION: i32 = 103;

pub const SER_DISK: i32 = 1 << 1;      
pub const SER_GETHASH: i32 = 1 << 2;   
pub const SER_NETWORK: i32 = 1 << 17;  



pub trait Serialize {
    fn get_serialize_size(&self, n_type: i32, n_version: i32) -> usize;

    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
        n_type: i32,
        n_version: i32,
    ) -> Result<(), std::io::Error>;

    fn unserialize<R: std::io::Read>(
        &mut self,
        reader: &mut R,
        n_type: i32,
        n_version: i32,
    ) -> Result<(), std::io::Error>;

    fn to_datastream(&self, n_type: i32, n_version: i32) -> Result<DataStream, std::io::Error> {
        let mut stream = DataStream::default();
        self.serialize(&mut stream, SER_DISK, VERSION)?;
        Ok(stream)
    }
}


pub trait Deserialize: Default {
    fn deserialize<R: std::io::Read>(
        reader: &mut R,
        n_type: i32,
        n_version: i32,
    ) -> Result<Self, std::io::Error>;
}


impl<T: Serialize + Default> Deserialize for T {
    fn deserialize<R: std::io::Read>(
        reader: &mut R,
        n_type: i32,
        n_version: i32,
    ) -> Result<Self, std::io::Error> {
        let mut value = T::default();
        value.unserialize(reader, n_type, n_version)?;
        Ok(value)
    }
}

pub trait GetHash {
    fn get_hash(&self) -> [u8; 32];
}


impl<T: Serialize> GetHash for T {
    fn get_hash(&self) -> [u8; 32] {
        let mut stream = DataStream::new(SER_GETHASH | SER_DISK, VERSION);
        self.serialize(&mut stream, SER_GETHASH | SER_DISK, VERSION)
            .expect("Serialization for hashing failed");
        let mut hasher = openssl::sha::Sha256::new();
        hasher.update(&stream.data);
        hasher.finish()
    }
}



macro_rules! impl_serialize_for_basic_types {
    ($($t:ty),*) => {
        $(
            impl Serialize for $t {
                fn get_serialize_size(&self, _n_type: i32, _n_version: i32) -> usize {
                    std::mem::size_of::<$t>()
                }

                fn serialize<W: std::io::Write>(
                    &self,
                    writer: &mut W,
                    _n_type: i32,
                    _n_version: i32,
                ) -> Result<(), std::io::Error> {
                    writer.write_all(&self.to_le_bytes())?;
                    Ok(())
                }

                fn unserialize<R: std::io::Read>(
                    &mut self,
                    reader: &mut R,
                    _n_type: i32,
                    _n_version: i32,
                ) -> Result<(), std::io::Error> {
                    let mut buffer = [0u8; std::mem::size_of::<$t>()];
                    reader.read_exact(&mut buffer)?;
                    *self = <$t>::from_le_bytes(buffer);
                    Ok(())
                }
            }
        )*
    };
}

macro_rules! impl_serialize_for_array {
    ($($N:expr),*) => {
        $(
            impl<T: Serialize + Default> Serialize for [T; $N] {
                fn get_serialize_size(&self, n_type: i32, n_version: i32) -> usize {
                    self.iter().map(|item| item.get_serialize_size(n_type, n_version)).sum()
                }

                fn serialize<W: std::io::Write>(
                    &self,
                    writer: &mut W,
                    n_type: i32,
                    n_version: i32,
                ) -> Result<(), std::io::Error> {
                    for item in self.iter() {
                        item.serialize(writer, n_type, n_version)?;
                    }
                    Ok(())
                }

                fn unserialize<R: std::io::Read>(
                    &mut self,
                    reader: &mut R,
                    n_type: i32,
                    n_version: i32,
                ) -> Result<(), std::io::Error> {
                    for item in self.iter_mut() {
                        item.unserialize(reader, n_type, n_version)?;
                    }
                    Ok(())
                }
            }
        )*
    };
}


macro_rules! impl_serialize_for_tuples {
    ($( $name:ident ),+) => {
        impl< $( $name: Serialize ),+ > Serialize for ( $( $name, )+ ) {
            fn get_serialize_size(&self, n_type: i32, n_version: i32) -> usize {
                let ($(ref $name,)+) = *self;
                0 $( + $name.get_serialize_size(n_type, n_version) )+
            }

            fn serialize<W: std::io::Write>(
                &self,
                writer: &mut W,
                n_type: i32,
                n_version: i32,
            ) -> Result<(), std::io::Error> {
                let ($(ref $name,)+) = *self;
                $( $name.serialize(writer, n_type, n_version)?; )+
                Ok(())
            }

            fn unserialize<R: std::io::Read>(
                &mut self,
                reader: &mut R,
                n_type: i32,
                n_version: i32,
            ) -> Result<(), std::io::Error> {
                let ($(ref mut $name,)+) = *self;
                $( $name.unserialize(reader, n_type, n_version)?; )+
                Ok(())
            }
        }
    };
}


impl Serialize for bool {
    fn get_serialize_size(&self, _n_type: i32, _n_version: i32) -> usize {
        1
    }

    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
        _n_type: i32,
        _n_version: i32,
    ) -> Result<(), std::io::Error> {
        writer.write_all(&[*self as u8])?;
        Ok(())
    }

    fn unserialize<R: std::io::Read>(
        &mut self,
        reader: &mut R,
        _n_type: i32,
        _n_version: i32,
    ) -> Result<(), std::io::Error> {
        let mut buf = [0u8];
        reader.read_exact(&mut buf)?;
        *self = buf[0] != 0;
        Ok(())
    }
}

impl Serialize for () {
    fn get_serialize_size(&self, _n_type: i32, _n_version: i32) -> usize {
        0
    }

    fn serialize<W: std::io::Write>(
        &self,
        _writer: &mut W,
        _n_type: i32,
        _n_version: i32,
    ) -> Result<(), std::io::Error> {
        Ok(())
    }

    fn unserialize<R: std::io::Read>(
        &mut self,
        _reader: &mut R,
        _n_type: i32,
        _n_version: i32,
    ) -> Result<(), std::io::Error> {
        Ok(())
    }
}


impl Serialize for char {
    fn get_serialize_size(&self, _n_type: i32, _n_version: i32) -> usize {
        4
    }

    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
        _n_type: i32,
        _n_version: i32,
    ) -> Result<(), std::io::Error> {
        let val = *self as u32;
        writer.write_all(&val.to_le_bytes())?;
        Ok(())
    }

    fn unserialize<R: std::io::Read>(
        &mut self,
        reader: &mut R,
        _n_type: i32,
        _n_version: i32,
    ) -> Result<(), std::io::Error> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        *self = char::from_u32(u32::from_le_bytes(buf))
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid char data"))?;
        Ok(())
    }
}


impl Serialize for String {
    fn get_serialize_size(&self, _n_type: i32, _n_version: i32) -> usize {
        get_size_of_compact_size(self.len() as u64) + self.len()
    }

    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
        _n_type: i32,
        _n_version: i32,
    ) -> Result<(), std::io::Error> {
        write_compact_size(writer, self.len() as u64)?;
        if !self.is_empty() {
            writer.write_all(self.as_bytes())?;
        }
        Ok(())
    }

    fn unserialize<R: std::io::Read>(
        &mut self,
        reader: &mut R,
        _n_type: i32,
        _n_version: i32,
    ) -> Result<(), std::io::Error> {
        let n_size = read_compact_size(reader)?;
        self.clear();
        self.reserve(n_size as usize);
        let mut buffer = vec![0u8; n_size as usize];
        reader.read_exact(&mut buffer)?;
        *self = String::from_utf8(buffer)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(())
    }
}


impl Serialize for &str {
    fn get_serialize_size(&self, _n_type: i32, _n_version: i32) -> usize {
        get_size_of_compact_size(self.len() as u64) + self.len()
    }

    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
        _n_type: i32,
        _n_version: i32,
    ) -> Result<(), std::io::Error> {
        write_compact_size(writer, self.len() as u64)?;
        if !self.is_empty() {
            writer.write_all(self.as_bytes())?;
        }
        Ok(())
    }

    fn unserialize<R: std::io::Read>(
        &mut self,
        _reader: &mut R,
        _n_type: i32,
        _n_version: i32,
    ) -> Result<(), std::io::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "&str is immutable and cannot be deserialized in place",
        ))
    }
}

impl Serialize for DataStream {
    fn get_serialize_size(&self, _n_type: i32, _n_version: i32) -> usize {
        get_size_of_compact_size(self.data.len() as u64) + self.data.len()
    }

    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
        _n_type: i32,
        _n_version: i32,
    ) -> Result<(), std::io::Error> {
        write_compact_size(writer, self.data.len() as u64)?;

        if !self.data.is_empty() {
            writer.write_all(&self.data)?;
        }
        Ok(())
    }

    fn unserialize<R: std::io::Read>(
        &mut self,
        reader: &mut R,
        _n_type: i32,
        _n_version: i32,
    ) -> Result<(), std::io::Error> {
        let n_size = read_compact_size(reader)?;

        self.data.clear();
        self.data.reserve(n_size as usize);

        let mut buffer = vec![0u8; n_size as usize];
        reader.read_exact(&mut buffer)?;
        self.data = buffer;

        self.read_pos = 0;
        self.write_pos = self.data.len();
        self.cursor = 0;
        self.state = 0;
        Ok(())
    }
}


impl<T: Serialize + Default> Serialize for Vec<T> {
    fn get_serialize_size(&self, n_type: i32, n_version: i32) -> usize {
        let mut n_size = get_size_of_compact_size(self.len() as u64);
        for item in self {
            n_size += item.get_serialize_size(n_type, n_version);
        }
        n_size
    }

    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
        n_type: i32,
        n_version: i32,
    ) -> Result<(), std::io::Error> {
        write_compact_size(writer, self.len() as u64)?;
        for item in self {
            item.serialize(writer, n_type, n_version)?;
        }
        Ok(())
    }

    fn unserialize<R: std::io::Read>(
        &mut self,
        reader: &mut R,
        n_type: i32,
        n_version: i32,
    ) -> Result<(), std::io::Error> {
        self.clear();
        let n_size = read_compact_size(reader)?;
        self.reserve(n_size as usize);
        for _ in 0..n_size {
            let mut item = T::default();
            item.unserialize(reader, n_type, n_version)?;
            self.push(item);
        }
        Ok(())
    }
}



pub fn get_size_of_compact_size(n_size: u64) -> usize {
    if n_size < 253 {
        std::mem::size_of::<u8>()
    } else if n_size <= u16::MAX as u64 {
        std::mem::size_of::<u8>() + std::mem::size_of::<u16>()
    } else if n_size <= u32::MAX as u64 {
        std::mem::size_of::<u8>() + std::mem::size_of::<u32>()
    } else {
        std::mem::size_of::<u8>() + std::mem::size_of::<u64>()
    }
}


pub fn write_compact_size<W: std::io::Write>(
    writer: &mut W,
    n_size: u64,
) -> Result<(), std::io::Error> {
    if n_size < 253 {
        writer.write_all(&[n_size as u8])?;
    } else if n_size <= u16::MAX as u64 {
        writer.write_all(&[253u8])?;
        writer.write_all(&(n_size as u16).to_le_bytes())?;
    } else if n_size <= u32::MAX as u64 {
        writer.write_all(&[254u8])?;
        writer.write_all(&(n_size as u32).to_le_bytes())?;
    } else {
        writer.write_all(&[255u8])?;
        writer.write_all(&n_size.to_le_bytes())?;
    }
    Ok(())
}

pub fn read_compact_size<R: std::io::Read>(reader: &mut R) -> Result<u64, std::io::Error> {
    let mut ch_size = [0u8; 1];
    reader.read_exact(&mut ch_size)?;
    let ch_size = ch_size[0];
    if ch_size < 253 {
        Ok(ch_size as u64)
    } else if ch_size == 253 {
        let mut n_size = [0u8; 2];
        reader.read_exact(&mut n_size)?;
        Ok(u16::from_le_bytes(n_size) as u64)
    } else if ch_size == 254 {
        let mut n_size = [0u8; 4];
        reader.read_exact(&mut n_size)?;
        Ok(u32::from_le_bytes(n_size) as u64)
    } else {
        let mut n_size = [0u8; 8];
        reader.read_exact(&mut n_size)?;
        Ok(u64::from_le_bytes(n_size))
    }
}


#[macro_export]
macro_rules! impl_serialize_from_string {
    ($ty:ty, $parse_fn:path) => {
        impl Serialize for $ty {
            fn get_serialize_size(
                &self, 
                n_type: i32, 
                n_version: i32) -> usize {
                self.to_string().get_serialize_size(n_type, n_version)
            }

            fn serialize<W: std::io::Write>(
                &self,
                writer: &mut W,
                n_type: i32,
                n_version: i32,
            ) -> Result<(), std::io::Error> {
                self.to_string().serialize(writer, n_type, n_version)
            }

            fn unserialize<R: std::io::Read>(
                &mut self,
                reader: &mut R,
                n_type: i32,
                n_version: i32,
            ) -> Result<(), std::io::Error> {
                let mut s = String::new();
                s.unserialize(reader, n_type, n_version)?;
                *self = $parse_fn(&s).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        concat!("Failed to parse ", stringify!($ty)),
                    )
                })?;
                Ok(())
            }
        }
    };
}

pub fn SerializeHash<T: Serialize>(obj: &T) -> [u8; 32] {
    let mut stream = DataStream::new(SER_GETHASH, VERSION);
    obj.serialize(&mut stream, SER_GETHASH, VERSION)
        .expect("Serialization for hashing failed");
    let mut hasher = openssl::sha::Sha256::new();
    hasher.update(&stream.data);
    hasher.finish()
}


impl_serialize_for_array!(1, 2, 4, 8, 12, 16, 32, 64, 128, 256);

impl_serialize_for_basic_types!(
    u8, u16, u32, u64, u128,
    i8, i16, i32, i64, i128,
    f32, f64
);

impl_serialize_for_tuples!(T1);
impl_serialize_for_tuples!(T1, T2);
impl_serialize_for_tuples!(T1, T2, T3);
impl_serialize_for_tuples!(T1, T2, T3, T4);
impl_serialize_for_tuples!(T1, T2, T3, T4, T5);
impl_serialize_for_tuples!(T1, T2, T3, T4, T5, T6);



#[derive(Debug, Clone, PartialEq)]
pub struct DataStream {
    pub data: Vec<u8>,      
    pub read_pos: usize,    
    pub write_pos: usize,   
    pub cursor: usize,      
    n_type: i32,            
    n_version: i32,         
    state: i16,            
}

impl DataStream {
    pub fn new(n_type: i32, n_version: i32) -> Self {
        DataStream {
            data: Vec::new(),
            read_pos: 0,
            write_pos: 0,
            cursor: 0,
            n_type,
            n_version,
            state: 0,
        }
    }


    pub fn write_data(&mut self, s: &[u8]) {
        self.seek_to_end();
        self.data.extend_from_slice(s);
    }

    pub fn extend_from_datastream(&mut self, other: &DataStream) {
        self.write_data(&other.data);
    }

    pub fn copy(&self) -> DataStream {
        let mut stream = DataStream::new(self.n_type, self.n_version);
        stream.write_data(&self.data);
        stream
    }

    pub fn read_value<T: Serialize + Default>(&mut self) -> Result<T, std::io::Error> {
        let mut value = T::default();
        value.unserialize(self, self.n_type, self.n_version)?;
        Ok(value)
    }

    pub fn begin_index(&self) -> usize {
        self.read_pos
    }

    pub fn end_index(&self) -> usize {
        self.data.len()
    }

    pub fn erase(&mut self, start: usize, end: Option<usize>) {
        let mut data = self.data.clone();
        let end_pos = end.unwrap_or(self.data.len()).min(self.data.len());
        if start < data.len() {
            data.drain(self.cursor + start..self.cursor + end_pos);
        }
        self.data = data;
        self.seek(self.cursor as u64);
    }

    pub fn compact(&mut self) {
        self.data.drain(0..self.read_pos);
        self.read_pos = 0;
    }

    pub fn unread_str(&self) -> &[u8] {
        &self.data[self.cursor..]
    }

    pub fn rewind(&mut self, n: usize) -> bool {
        if n > self.read_pos {
            false
        } else {
            self.read_pos -= n;
            true
        }
    }

    pub fn ignore(&mut self, n_size: usize) -> &mut Self {
        assert!(n_size >= 0);
        let n_read_pos_next = self.read_pos + n_size;

        if n_read_pos_next >= self.data.len() {
            if n_read_pos_next > self.data.len() {
                panic!("DataStream::ignore() : end of data");
            }
            self.read_pos = 0;
            self.data.clear();
            return self;
        }

        self.read_pos = n_read_pos_next;
        self
    }

    pub fn raw_write(&mut self, s: &[u8], pos: usize) {
        let original_pos = self.cursor;
        let mut data = self.data.clone();
        let end_pos = pos + s.len();
        if end_pos <= data.len() {
            data[pos..end_pos].copy_from_slice(s);
        }
        self.data = data;
        self.seek(original_pos as u64);
    }

    pub fn raw_read_buf(&self, start: usize, size: usize) -> &[u8] {
        &self.data[start..start + size]
    }

    pub fn seek(&mut self, position: u64) {
        self.cursor = position as usize;
    }

    pub fn seek_to_end(&mut self) {
        self.cursor = self.data.len();
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn empty(&self) -> bool {
        self.size() == 0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }

    pub fn to_hex(&self) -> String {
        self.data.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join("")
    }

    pub fn to_string(&self) -> String {
        String::from_utf8_lossy(&self.data[self.cursor..]).to_string()
    }

    pub fn write_obj<T: Serialize + ?Sized>(&mut self, obj: &T) -> Result<(), std::io::Error> {
        obj.serialize(self, self.n_type, self.n_version)
    }

    pub fn read_obj<T: Serialize>(&mut self, obj: &mut T) -> Result<(), std::io::Error> {
        obj.unserialize(self, self.n_type, self.n_version)
    }

    pub fn stream_in<T: Serialize + ?Sized>(&mut self, obj: &T) -> Result<(), std::io::Error> {
        self.write_obj(obj)
    }

    pub fn stream_out<T: Serialize + ?Sized + Default>(&mut self) -> Result<T, std::io::Error> {
        self.read_value()
    }
}



impl std::io::Read for DataStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        let available = self.data.len() - self.read_pos;
        let to_read = buf.len().min(available);
        if to_read == 0 {
            return Ok(0);
        }
        buf[..to_read].copy_from_slice(&self.data[self.read_pos..self.read_pos + to_read]);
        self.read_pos += to_read;
        if to_read < buf.len() {
            self.state |= 0x04; 
            buf[to_read..].fill(0); 
        }
        if self.read_pos >= self.data.len() {
            self.data.clear();
            self.read_pos = 0;
        }
        Ok(to_read)
    }
}


impl Default for DataStream {
    fn default() -> Self {
        DataStream::new(SER_NETWORK, VERSION)
    }
}

impl std::io::Write for DataStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.data.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

impl From<Vec<u8>> for DataStream {
    fn from(data: Vec<u8>) -> Self {
        DataStream {
            data: data.clone(),
            read_pos: 0,
            write_pos: data.len(),
            cursor: 0,
            n_type: SER_NETWORK,
            n_version: VERSION,
            state: 0,
        }
    }
}


impl<T: Serialize> std::ops::Shl<T> for &mut DataStream {
    type Output = Self;

    fn shl(self, rhs: T) -> Self::Output {
        self.write_obj(&rhs).expect("Serialization failed");
        self
    }
}

impl<T: Serialize> std::ops::Shl<T> for DataStream {
    type Output = Self;

    fn shl(mut self, rhs: T) -> Self::Output {
        self.write_obj(&rhs).expect("Serialization failed");
        self
    }
}

impl<T: Serialize> std::ops::Shr<&mut T> for &mut DataStream {
    type Output = Self;

    fn shr(mut self, val: &mut T) -> Self::Output {
        val.unserialize(self, self.n_type, self.n_version).expect("Deserialization failed");
        self
    }
}

impl AsRef<[u8]> for DataStream {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}



#[derive(Default, Clone)]
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_bool() {
        let mut stream = DataStream::new(SER_DISK, VERSION);
        let value = true;

        (&mut stream << value);
        assert_eq!(stream.data.len(), value.get_serialize_size(SER_DISK, VERSION));

        let mut read_value = false;
        (&mut stream >> &mut read_value);
        assert_eq!(value, read_value);
    }

    #[test]
    fn test_serialize_char() {
        let mut stream = DataStream::new(SER_DISK, VERSION);
        let value = 'ß';

        (&mut stream << value);
        assert_eq!(stream.data.len(), value.get_serialize_size(SER_DISK, VERSION));

        let mut read_value = '\0';
        (&mut stream >> &mut read_value);
        assert_eq!(value, read_value);
    }

    #[test]
    fn test_serialize_deserialize_u32() {
        let value: u32 = 42;
        let mut stream = DataStream::default();
        value.serialize(&mut stream, SER_DISK, VERSION).unwrap();
        let mut deserialized = 0u32;
        deserialized.unserialize(&mut stream, SER_DISK, VERSION).unwrap();
        assert_eq!(value, deserialized);
    }

    #[test]
    fn test_serialize_deserialize_string() {
        let value = String::from("hello world");
        let mut stream = DataStream::default();
        value.serialize(&mut stream, SER_DISK, VERSION).unwrap();
        let mut deserialized = String::new();
        deserialized.unserialize(&mut stream, SER_DISK, VERSION).unwrap();
        assert_eq!(value, deserialized);
    }

    #[test]
    fn test_get_hash_u32() {
        let value: u32 = 123456;
        let hash1 = value.get_hash();
        let hash2 = SerializeHash(&value);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_serialize_deserialize_vec_u8() {
        let vec = vec![1u8, 2, 3, 4, 5];
        let mut stream = DataStream::default();
        vec.serialize(&mut stream, SER_DISK, VERSION).unwrap();

        let mut deserialized: Vec<u8> = Vec::new();
        deserialized.unserialize(&mut stream, SER_DISK, VERSION).unwrap();
        assert_eq!(vec, deserialized);
    }

    #[test]
    fn test_serialize_deserialize_tuple() {
        let value = (123u32, 3.14f64, true);
        let mut stream = DataStream::default();
        value.serialize(&mut stream, SER_DISK, VERSION).unwrap();

        let mut deserialized = (0u32, 0.0f64, false);
        deserialized.unserialize(&mut stream, SER_DISK, VERSION).unwrap();

        assert_eq!(value, deserialized);
    }

    #[test]
    fn test_to_datastream_roundtrip() {
        let original = String::from("roundtrip test");
        let stream = original.to_datastream(SER_DISK, VERSION).unwrap();
        let mut result = String::new();
        result.unserialize(&mut stream.clone(), SER_DISK, VERSION).unwrap();
        assert_eq!(original, result);
    }

    #[test]
    fn test_serialize_deserialize_array() {
        let arr = [10u8, 20, 30, 40];
        let mut stream = DataStream::default();
        arr.serialize(&mut stream, SER_DISK, VERSION).unwrap();

        let mut deserialized = [0u8; 4];
        deserialized.unserialize(&mut stream, SER_DISK, VERSION).unwrap();
        assert_eq!(arr, deserialized);
    }

    #[test]
    fn test_stream_in_out() {
        let mut stream = DataStream::new(SER_DISK, VERSION);

        let val_i32: i32 = -42;
        let val_u32: u32 = 1234;
        let val_string = String::from("hello");
        let val_vec: Vec<i32> = vec![1, 2, 3, 4];

        stream.stream_in(&val_i32).unwrap();
        stream.stream_in(&val_u32).unwrap();
        stream.stream_in(&val_string).unwrap();
        stream.stream_in(&val_vec).unwrap();

        let o_a = stream.stream_out::<i32>().unwrap();
        let o_b = stream.stream_out::<u32>().unwrap();
        let o_c = stream.stream_out::<String>().unwrap();
        let o_d = stream.stream_out::<Vec<i32>>().unwrap();

        assert_eq!(o_a, val_i32);
        assert_eq!(o_b, val_u32);
        assert_eq!(o_c, val_string);
        assert_eq!(o_d, val_vec);
    }

    #[test]
    fn test_serialize_nested_structs() {
        let mut stream = DataStream::new(SER_DISK, VERSION);
        let inner = InnerStruct { flag: 7, data: 999 };
        let example = ExampleStruct {
            id: 42,
            name: "NestedTest".to_string(),
            inner: inner.clone(),
            values: vec![100, 200],
        };

        (&mut stream << example.clone());

        let mut read_example = ExampleStruct::default();
        (&mut stream >> &mut read_example);

        assert_eq!(example.id, read_example.id);
        assert_eq!(example.name, read_example.name);
        assert_eq!(example.inner.flag, read_example.inner.flag);
        assert_eq!(example.inner.data, read_example.inner.data);
        assert_eq!(example.values, read_example.values);
    }
}
