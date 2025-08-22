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


use std::path::PathBuf;
use clap::ValueEnum;


use std::io::{
    Read, 
    Write
};



use std::sync::{
    Arc, 
    LazyLock
};


use nym_sdk::mixnet::{
    AnonymousSenderTag, 
    IncludedSurbs, 
    MixnetClient, 
    MixnetClientBuilder, 
    MixnetMessageSender, 
    Recipient, 
    StoragePaths
};

use serialize::{
    DataStream, 
    GetHash, 
    Serialize, 
    get_size_of_compact_size, 
    read_compact_size, 
    write_compact_size
};


use tokio::sync::{
    Mutex, broadcast
};
use tokio::time::{
    sleep, 
    Duration
};

use std::collections::HashMap;



////////////////////////////////////////// SockAddr


#[derive(PartialEq, Eq, Clone, Debug)]
pub enum SockAddr {
    NymAddress(Recipient),
    SenderTag(AnonymousSenderTag),
    Null,
}

impl Default for SockAddr {
    fn default() -> Self {
        SockAddr::Null
    }
}

impl Serialize for SockAddr {
    fn get_serialize_size(&self, _n_type: i32, _n_version: i32) -> usize {
        let base_size = std::mem::size_of::<u8>();
        match self {
            SockAddr::Null => base_size,
            SockAddr::SenderTag(tag) => {
                let s = tag.to_string();
                base_size + get_size_of_compact_size(s.len() as u64) + s.len()
            }
            SockAddr::NymAddress(addr) => {
                let s = addr.to_string();
                base_size + get_size_of_compact_size(s.len() as u64) + s.len()
            }
        }
    }

    fn serialize<W: Write>(&self, writer: &mut W, _n_type: i32, _n_version: i32) -> Result<(), std::io::Error> {
        match self {
            SockAddr::Null => writer.write_all(&[0u8]),
            SockAddr::SenderTag(tag) => {
                writer.write_all(&[1u8])?;
                let s = tag.to_string();
                write_compact_size(writer, s.len() as u64)?;
                if !s.is_empty() {
                    writer.write_all(s.as_bytes())?;
                }
                Ok(())
            }
            SockAddr::NymAddress(addr) => {
                writer.write_all(&[2u8])?;
                let s = addr.to_string();
                write_compact_size(writer, s.len() as u64)?;
                if !s.is_empty() {
                    writer.write_all(s.as_bytes())?;
                }
                Ok(())
            }
        }
    }

    fn unserialize<R: Read>(&mut self, reader: &mut R, _n_type: i32, _n_version: i32) -> Result<(), std::io::Error> {
        let mut type_byte = [0u8];
        reader.read_exact(&mut type_byte)?;
        *self = match type_byte[0] {
            0 => SockAddr::Null,
            1 => {
                let n_size = read_compact_size(reader)?;
                let mut buffer = vec![0u8; n_size as usize];
                reader.read_exact(&mut buffer)?;
                let s = String::from_utf8(buffer)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                let tag = AnonymousSenderTag::try_from_base58_string(&s)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Invalid AnonymousSenderTag: {}", e)))?;
                SockAddr::SenderTag(tag)
            }
            2 => {
                let n_size = read_compact_size(reader)?;
                let mut buffer = vec![0u8; n_size as usize];
                reader.read_exact(&mut buffer)?;
                let s = String::from_utf8(buffer)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                let recipient = Recipient::try_from_base58_string(&s)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("Invalid Recipient: {}", e)))?;
                SockAddr::NymAddress(recipient)
            }
            _ => SockAddr::Null,
        };
        Ok(())
    }
}

impl From<Recipient> for SockAddr {
    fn from(recipient: Recipient) -> Self {
        SockAddr::NymAddress(recipient)
    }
}

impl From<AnonymousSenderTag> for SockAddr {
    fn from(tag: AnonymousSenderTag) -> Self {
        SockAddr::SenderTag(tag)
    }
}

impl From<&str> for SockAddr {
    fn from(s: &str) -> Self {
        match Recipient::try_from_base58_string(s) {
            Ok(recipient) => SockAddr::NymAddress(recipient),
            Err(_) => SockAddr::Null,
        }
    }
}

impl ToString for SockAddr {
    fn to_string(&self) -> String {
        match self {
            SockAddr::NymAddress(recipient) => recipient.to_string(),
            SockAddr::SenderTag(tag) => tag.to_string(),
            SockAddr::Null => "null".to_string(),
        }
    }
}

impl SockAddr {
    pub fn is_individual(&self) -> bool {
        matches!(self, SockAddr::NymAddress(_))
    }

    pub fn is_anonymous(&self) -> bool {
        matches!(self, SockAddr::SenderTag(_))
    }

    pub fn is_null(&self) -> bool {
        matches!(self, SockAddr::Null)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SocketMessage {
    pub from: SockAddr, 
    pub data: Vec<u8>,  
    pub time: u64,      
}

serialize_derive::impl_serialize_for_struct! {
    target SocketMessage {
        readwrite(self.from); 
        readwrite(self.data); 
        readwrite(self.time); 
    }
}


////////////////////////////////////////// SocketMessage

impl SocketMessage {
    pub fn new(from: SockAddr, data: Vec<u8>) -> Self {
        Self {
            from,
            data,
            time: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        }
    }

    pub fn is_from_individual(&self) -> bool {
        self.from.is_individual()
    }

    pub fn is_from_anonymous(&self) -> bool {
        self.from.is_anonymous()
    }

    pub fn is_from_null(&self) -> bool {
        self.from.is_null()
    }

    pub fn is_older_than(&self, threshold_secs: u64) -> bool {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        now.saturating_sub(self.time) > threshold_secs
    }
}



////////////////////////////////////////// Clients
 
#[derive(Clone)]
pub struct StandardClient {
    pub path: String,
    pub dir: PathBuf,
    pub client: Arc<Mutex<Option<MixnetClient>>>,
}

#[derive(Clone)]
pub struct EphemeralClient {
    pub client: Arc<Mutex<Option<MixnetClient>>>,
}

impl StandardClient {
    pub async fn new(client_path: &str) -> Option<Self> {
        let config_dir = PathBuf::from(client_path);
        let storage_paths = match StoragePaths::new_from_dir(&config_dir) {
            Ok(paths) => paths,
            Err(e) => {
                println!("StandardClient()- Failed to initialize storage paths at '{}': {}", client_path, e);
                return None;
            }
        };

        let mixnet_client = match MixnetClientBuilder::new_with_default_storage(storage_paths).await {
            Ok(builder) => builder,
            Err(e) => {
                println!("StandardClient() - Failed to initialize Mixnet client builder: {}", e);
                return None;
            }
        }
        .build()
        .map_err(|e| println!("StandardClient() - Failed to build Mixnet client: {}", e))
        .ok()?
        .connect_to_mixnet()
        .await
        .map_err(|e| println!("StandardClient() - Failed to connect to Mixnet: {}", e))
        .ok()?;

        Some(Self {
            path: client_path.to_string(),
            dir: config_dir,
            client: Arc::new(Mutex::new(Some(mixnet_client))),
        })
    }
}

impl EphemeralClient {
    pub async fn new() -> Option<Self> {
        let client = MixnetClientBuilder::new_ephemeral()
            .build()
            .map_err(|e| println!("EphemeralClient() - Failed to build ephemeral Mixnet client: {}", e))
            .ok()?
            .connect_to_mixnet()
            .await
            .map_err(|e| println!("EphemeralClient() - Failed to connect ephemeral client to Mixnet: {}", e))
            .ok()?;

        Some(Self {
            client: Arc::new(Mutex::new(Some(client))),
        })
    }
}

#[derive(Clone)]
pub enum Client {
    Standard(StandardClient),
    Ephemeral(EphemeralClient),
}

#[macro_export]
macro_rules! impl_getaddr {
    ($t:ty) => {
        impl $t {
            pub async fn getaddr(&self) -> Option<Recipient> {
                self.client
                    .lock()
                    .await
                    .as_ref()
                    .map(|client| client.nym_address().clone())
            }
        }
    };
}

#[macro_export]
macro_rules! impl_getsockaddr {
    ($t:ty) => {
        impl $t {
            pub async fn getsockaddr(&self) -> Option<SockAddr> {
                self.client
                    .lock()
                    .await
                    .as_ref()
                    .map(|client| SockAddr::NymAddress(client.nym_address().clone()))
            }
        }
    };
}

#[macro_export]
macro_rules! impl_disconnect {
    ($t:ty) => {
        impl $t {
            pub async fn disconnect(&self) {
                let mut client = self.client.lock().await;
                if let Some(c) = client.take() {
                    c.disconnect().await;
                }
            }
        }
    };
}

impl_getaddr!(StandardClient);
impl_getaddr!(EphemeralClient);
impl_getsockaddr!(StandardClient);
impl_getsockaddr!(EphemeralClient);
impl_disconnect!(StandardClient);
impl_disconnect!(EphemeralClient);



////////////////////////////////////////// Socket


pub static STOP_SIGNAL: LazyLock<Arc<Mutex<Option<broadcast::Sender<bool>>>>> =
    LazyLock::new(|| Arc::new(Mutex::new(None)));

#[derive(Debug, Clone, Copy, PartialEq, ValueEnum)]
pub enum SocketMode {
    Anonymous,
    Individual,
    Null,
}

pub enum To {
    SockAddr(SockAddr),
    Recipient(Recipient),
    String(String),
}

impl From<SockAddr> for To {
    fn from(address: SockAddr) -> Self {
        To::SockAddr(address)
    }
}

impl From<Recipient> for To {
    fn from(recipient: Recipient) -> Self {
        To::Recipient(recipient)
    }
}

impl From<&str> for To {
    fn from(s: &str) -> Self {
        To::String(s.to_string())
    }
}

#[macro_export]
macro_rules! impl_to_for {
    ($type:ty) => {
        impl From<$type> for To {
            fn from(addr: $type) -> Self {
                To::SockAddr(addr.address)
            }
        }
    };
}

#[derive(Debug, Default, Clone)]
pub struct SocketMetrics {
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
}

#[derive(Clone)]
pub struct Socket {
    pub client: Client,
    pub mode: SocketMode,
    pub metrics: SocketMetrics,
    pub already_send: Vec<[u8; 32]>,
    pub check_stale: bool,
    pub stale_expiration_time: u64,
    pub muted_addresses: Arc<Mutex<HashMap<[u8; 32], u64>>>,
    pub recv: Arc<Mutex<Vec<SocketMessage>>>,
}

impl Socket {
    pub async fn new_standard(client_path: &str, mode: SocketMode) -> Option<Self> {
        let standard_client = StandardClient::new(client_path).await?;
        Some(Self {
            client: Client::Standard(standard_client),
            mode,
            metrics: SocketMetrics::default(),
            already_send: Vec::new(),
            check_stale: false,
            stale_expiration_time: u64::MAX,
            muted_addresses: Arc::new(Mutex::new(HashMap::new())),
            recv: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub async fn new_ephemeral(mode: SocketMode) -> Option<Self> {
        let ephemeral_client = EphemeralClient::new().await?;
        Some(Self {
            client: Client::Ephemeral(ephemeral_client),
            mode,
            metrics: SocketMetrics::default(),
            already_send: Vec::new(),
            check_stale: false,
            stale_expiration_time: u64::MAX,
            muted_addresses: Arc::new(Mutex::new(HashMap::new())),
            recv: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub async fn mute_address(&self, address: impl Into<SockAddr>, duration_secs: u64) {
        let address = address.into();
        let addr_hash = address.get_hash(); 
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expiration_time = current_time + duration_secs;

        let mut muted = self.muted_addresses.lock().await;
        muted.insert(addr_hash, expiration_time);
        println!("[*] Socket::mute_address() - Muted address with hash {:x?} until timestamp {}",
            addr_hash, 
            expiration_time);
    }

    pub async fn unmute_address(&self, address: impl Into<SockAddr>) {
        let address = address.into();
        let addr_hash = address.get_hash();
        let mut muted = self.muted_addresses.lock().await;
        if muted.remove(&addr_hash).is_some() {
            println!("[*] Socket::unmute_address() - Unmuted address with hash {:x?}", addr_hash);
        }
    }

    pub async fn listen(&mut self) {
        if self.check_stale && self.stale_expiration_time == u64::MAX {
            println!("[!] Socket::listen() - Stale checking enabled but expiration time is invalid.");
            return;
        }

        let mut rx = {
            let mut stop_signal = STOP_SIGNAL.lock().await;
            if stop_signal.is_none() {
                let (tx, rx) = broadcast::channel(1);
                *stop_signal = Some(tx);
                rx
            } else {
                stop_signal.as_ref().unwrap().subscribe()
            }
        };

        loop {
            tokio::select! {
                Ok(signal) = rx.recv() => {
                    if signal {
                        println!("[!] Socket::listen() - Stop signal received.");
                        break;
                    }
                }

                _ = tokio::time::sleep(tokio::time::Duration::from_secs(10)) => {
                    let inner_client = match &self.client {
                        Client::Standard(c) => c.client.clone(),
                        Client::Ephemeral(c) => c.client.clone(),
                    };

                    let mut guard = inner_client.lock().await;
                    let client_ref = match guard.as_mut() {
                        Some(c) => c,
                        None => {
                            println!("[!] Socket::listen() - Client not initialized.");
                            return;
                        }
                    };

                    let messages_result = tokio::time::timeout(
                        tokio::time::Duration::from_secs(5),
                        client_ref.wait_for_messages(),
                    ).await;

                    match messages_result {
                        Ok(Some(messages)) => {
                            let current_time = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs();

                            {
                                let mut muted = self.muted_addresses.lock().await;
                                muted.retain(|_, &mut expiration| expiration > current_time);
                            }

                            for message in messages {
                                let mut stream = DataStream::default();
                                stream.write(message.message.as_slice());

                                match stream.stream_out::<SocketMessage>() {
                                    Ok(mut msg) => {
                                        if self.check_stale && msg.is_older_than(self.stale_expiration_time) {
                                            println!(
                                                "[!] Socket::listen() - Dropped stale message from {:?} ({}s old)",
                                                msg.from, current_time - msg.time
                                            );
                                            continue;
                                        }

                                        if let Some(sender_tag) = message.sender_tag {
                                            msg.from = SockAddr::from(sender_tag);
                                        }

                                        let is_muted = {
                                            let muted = self.muted_addresses.lock().await;
                                            muted.get(&msg.from.get_hash()).map_or(false, |&expiration| expiration > current_time)
                                        };

                                        if is_muted {
                                            println!("[!] Socket::listen() - Skipped muted message from {:?}", msg.from);
                                            continue;
                                        }

                                        let mut recv = self.recv.lock().await;
                                        recv.push(msg.clone());

                                        self.metrics.total_bytes_received += message.message.len() as u64;
                                    }
                                    Err(_) => {
                                        println!("[!] Socket::listen() - Failed to deserialize message.");
                                        continue;
                                    }
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(_) => {}
                    }
                }
            }
        }
    }

    pub async fn send(&mut self, data: Vec<u8>, to: impl Into<To>) -> bool {
        let recipient = match to.into() {
            To::SockAddr(a) => a,
            To::Recipient(r) => SockAddr::NymAddress(r),
            To::String(s) => match Recipient::try_from_base58_string(&s) {
                Ok(r) => SockAddr::NymAddress(r),
                Err(e) => {
                    println!("[!] Socket::send() - Invalid address string '{}': {:?}", s, e);
                    return false;
                }
            },
        };

        let surbs = match self.mode {
            SocketMode::Individual => IncludedSurbs::ExposeSelfAddress,
            SocketMode::Anonymous => {
                if self.already_send.contains(&recipient.get_hash()) {
                    IncludedSurbs::ExposeSelfAddress
                } else {
                    IncludedSurbs::Amount(10)
                }
            }
            SocketMode::Null => {
                println!("[!] Socket::send() - Null mode. No sending allowed.");
                return false;
            }
        };

        let inner_client = match &self.client {
            Client::Standard(c) => c.client.clone(),
            Client::Ephemeral(c) => c.client.clone(),
        };
        let mut guard = inner_client.lock().await;
        let client_ref = match guard.as_mut() {
            Some(c) => c,
            None => {
                println!("[!] Socket::send() - Client not initialized.");
                return false;
            }
        };

        let self_addr = match self.mode {
            SocketMode::Anonymous => SockAddr::default(),
            _ => SockAddr::from(client_ref.nym_address().clone()),
        };

        let message = SocketMessage::new(self_addr, data.clone());
        let mut stream = DataStream::default();
        stream.stream_in(&message);
        let serialized: Vec<u8> = stream.data;

        let sent = match recipient {
            SockAddr::NymAddress(ref recipient) => {
                client_ref
                    .send_message(*recipient, serialized.clone(), surbs)
                    .await
                    .is_ok()
            }
            SockAddr::SenderTag(ref reply_addr) => {
                client_ref
                    .send_reply(*reply_addr, serialized.clone())
                    .await
                    .is_ok()
            }
            SockAddr::Null => false,
        };

        if sent {
            self.metrics.total_bytes_sent += serialized.len() as u64;
            println!("[*] Socket::send() - Message sent to {:?} in mode {:?}", recipient, self.mode);
            if self.mode == SocketMode::Anonymous && !self.already_send.contains(&recipient.get_hash()) {
                self.already_send.push(recipient.get_hash());
            }
        } else {
            println!("[!] Socket::send() - Failed to send message to {:?}", recipient);
        }

        sent
    }

    pub async fn disconnect(&self) {
        if let Some(tx) = STOP_SIGNAL.lock().await.as_ref() {
            let _ = tx.send(true);
        }
        match &self.client {
            Client::Standard(c) => c.disconnect().await,
            Client::Ephemeral(c) => c.disconnect().await,
        }
    }

    pub async fn getaddr(&self) -> Option<Recipient> {
        match &self.client {
            Client::Standard(c) => c.getaddr().await,
            Client::Ephemeral(c) => c.getaddr().await,
        }
    }

    pub async fn getsockaddr(&self) -> Option<SockAddr> {
        match &self.client {
            Client::Standard(c) => c.getsockaddr().await,
            Client::Ephemeral(c) => c.getsockaddr().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    const TEST_RECIPIENT: &str = "CokKZeJDb2u4qJRWbptk9HcEJ8TJsjWmfoRaEUe1Ei8M.2bzg9gjoNfkF7rwrh5WK2fUXPpf4JqcS9iEvDmD9DCNw@7ntzmDZRvG4a1pnDBU4Bg1RiAmLwmqXV5sZGNw68Ce14";

    #[test]
    fn test_default_sockaddr() {
        let sockaddr = SockAddr::default();
        assert_eq!(sockaddr, SockAddr::Null);
        assert!(sockaddr.is_null());

        let mut stream = DataStream::default();
        stream.stream_in(&sockaddr).unwrap();

        let deserialized = stream.stream_out::<SockAddr>().unwrap();
        assert_eq!(sockaddr, deserialized);
    }

    #[test]
    fn test_from_recipient() {
        let recipient = Recipient::try_from_base58_string(TEST_RECIPIENT)
            .expect("Invalid test recipient string");
        
        let sockaddr = SockAddr::from(recipient);
        assert!(sockaddr.is_individual());

        let mut stream = DataStream::default();
        stream.stream_in(&sockaddr).unwrap();

        let deserialized = stream.stream_out::<SockAddr>().unwrap();
        assert_eq!(sockaddr, deserialized);
    }

    #[test]
    fn test_from_sender_tag() {
        let mut rng = OsRng;
        let tag = AnonymousSenderTag::new_random(&mut rng);
        let sockaddr = SockAddr::from(tag);
        assert!(sockaddr.is_anonymous());

        let mut stream = DataStream::default();
        stream.stream_in(&sockaddr).unwrap();

        let deserialized = stream.stream_out::<SockAddr>().unwrap();
        assert_eq!(sockaddr, deserialized);
    }    

    #[test]
    fn test_from_string() {
        let sockaddr = SockAddr::from(TEST_RECIPIENT);
        assert!(sockaddr.is_individual());

        let mut stream = DataStream::default();
        stream.stream_in(&sockaddr).unwrap();

        let deserialized = stream.stream_out::<SockAddr>().unwrap();
        assert_eq!(sockaddr, deserialized);
    } 

    fn _test_socket_message_from_individual() -> SocketMessage {
        let address = SockAddr::from(TEST_RECIPIENT);
        let data = b"hello world".to_vec();
        SocketMessage::new(address, data)
    }

    fn _test_socket_message_from_anonymous() -> (SocketMessage, AnonymousSenderTag) {
        let address = SockAddr::default();
        let data = b"hello world".to_vec();
        let mut message = SocketMessage::new(address, data);
        let mut rng = OsRng;
        let tag = AnonymousSenderTag::new_random(&mut rng);
        let address = SockAddr::from(tag.clone());
        message.from = address;
        (message, tag)
    }

    fn _test_socket_message_from_null() -> SocketMessage {
        let address = SockAddr::default();
        let data = b"hello world".to_vec();
        SocketMessage::new(address, data)
    }

    #[test]
    fn test_socket_message_from_individual() {
        let message = _test_socket_message_from_individual();
        assert!(message.is_from_individual());
        assert_eq!(message.from, SockAddr::from(TEST_RECIPIENT));
        assert!(!message.is_older_than(120));
    }

    #[test]
    fn test_socket_message_from_anonymous() {
        let (message, tag) = _test_socket_message_from_anonymous();
        assert!(message.is_from_anonymous());
        assert_eq!(message.from, SockAddr::from(tag));
        assert!(!message.is_older_than(120));
    }

    #[test]
    fn test_socket_message_from_null() {
        let message = _test_socket_message_from_null();
        assert!(message.is_from_null());
        assert_eq!(message.from, SockAddr::default());
        assert!(!message.is_older_than(120));
    }

    #[test]
    fn test_socket_message_serialization() {
        let message = _test_socket_message_from_individual();
        let mut stream = DataStream::default();
        stream.stream_in(&message).unwrap();

        let deserialized = stream.stream_out::<SocketMessage>().unwrap();
        assert_eq!(message.from, deserialized.from);
        assert_eq!(message.data, deserialized.data);
        assert_eq!(message.time, deserialized.time);
    }

    #[tokio::test]
    async fn test_ephemeral_client_creation_and_methods() {
        sleep(Duration::from_secs(3)).await;
        let client = EphemeralClient::new().await;
        assert_eq!(client.is_some(), true);
        let client = client.unwrap();

        let addr = client.getsockaddr().await;
        assert_eq!(addr.is_some(), true);

        let recipient = client.getaddr().await;
        assert_eq!(recipient.is_some(), true);

        client.disconnect().await;
    }

    #[tokio::test]
    async fn test_standard_client_creation_and_methods() {
        sleep(Duration::from_secs(3)).await;
        let temp_path = std::env::temp_dir().join("nym_test_configuration");
        std::fs::create_dir_all(&temp_path).unwrap();

        let client = StandardClient::new(temp_path.to_str().unwrap()).await;

        if let Some(client) = client {
            let addr = client.getsockaddr().await;
            assert_eq!(addr.is_some(), true);

            let recipient = client.getaddr().await;
            assert_eq!(recipient.is_some(), true);

            client.disconnect().await;
        }

        std::fs::remove_dir_all(&temp_path).unwrap();
    }

    #[tokio::test]
    async fn test_standard_socket_send_receive_with_filters() {
        sleep(Duration::from_secs(3)).await;

        let mut socket = Socket::new_ephemeral(SocketMode::Individual)
            .await
            .expect("Failed to create socket");

        let mut listen_socket = socket.clone();
        tokio::spawn(async move {
            listen_socket.listen().await;
        });

        let addr = socket.getsockaddr().await.expect("Failed to get address");
        let msg_data = b"Hello Nym".to_vec();
        let sent = socket.send(msg_data.clone(), addr.clone()).await;
        assert!(sent, "Failed to send message to self in Individual mode");

        let mut anonymous_socket = Socket::new_ephemeral(SocketMode::Anonymous)
            .await
            .expect("Failed to create anonymous socket");

        let sent = anonymous_socket.send(msg_data.clone(), addr.clone()).await;
        assert!(sent, "Failed to send message to self in Anonymous mode");

        sleep(Duration::from_secs(6)).await;

        let received_messages: Vec<_> = {
            let mut messages = socket.recv.lock().await;
            messages.drain(..).collect()
        };

        for message in &received_messages {
            println!("Raw data: {:?}", message.data);
            println!("As string: {}", String::from_utf8_lossy(&message.data));
            println!("Sender: {:?}", message.from);
            println!("Time: {:?}", message.time);
        }

        let messages_from_expected_sender: Vec<_> = received_messages
            .iter()
            .filter(|m| m.from == addr)
            .collect();
        println!("Messages from expected sender: {}", messages_from_expected_sender.len());

        let individual_messages: Vec<_> = received_messages
            .iter()
            .filter(|m| m.is_from_individual())
            .collect();
        println!("Individual messages: {}", individual_messages.len());

        let anonymous_messages: Vec<_> = received_messages
            .iter()
            .filter(|m| m.is_from_anonymous())
            .collect();
        println!("Anonymous messages: {}", anonymous_messages.len());

        let null_messages: Vec<_> = received_messages
            .iter()
            .filter(|m| m.is_from_null())
            .collect();
        println!("Null messages: {}", null_messages.len());

        let old_messages: Vec<_> = received_messages
            .iter()
            .filter(|m| m.is_older_than(100))
            .collect();
        println!("Messages older than 100 seconds: {}", old_messages.len());

        let message_texts: Vec<String> = received_messages
            .iter()
            .map(|m| String::from_utf8_lossy(&m.data).to_string())
            .collect();
        println!("All message texts: {:?}", message_texts);

        assert!(!messages_from_expected_sender.is_empty(), "No messages received from expected sender");

        for message in received_messages {
            let msg_data = if message.is_from_anonymous() {
                b"Hey anon".to_vec()
            } else if message.is_from_individual() {
                b"Hey individual".to_vec()
            } else {
                b"Hey there".to_vec()
            };

            let sent = socket.send(msg_data.clone(), message.from.clone()).await;
            assert!(sent, "Failed to send reply to received message");
        }
    }


    
    #[tokio::test]
    async fn test_mute_address() {
        let mut socket = Socket::new_ephemeral(SocketMode::Individual)
            .await
            .expect("Failed to create socket");

        let mut listen_socket = socket.clone();
        tokio::spawn(async move {
            listen_socket.listen().await;
        });

        let addr = socket.getsockaddr().await.expect("Failed to get address");
        let addr_hash = addr.get_hash(); 

        socket.mute_address(addr.clone(), 30).await;

        {
            let muted = socket.muted_addresses.lock().await;
            assert!(muted.contains_key(&addr_hash), "Address hash should be muted");
        }

        let msg_data = b"Test message".to_vec();
        let sent = socket.send(msg_data.clone(), addr.clone()).await;
        assert!(sent, "Failed to send message");

        sleep(Duration::from_secs(10)).await;

        {
            let received_messages = socket.recv.lock().await;
            assert!(received_messages.is_empty(), "Received messages from muted address");
        } 

        sleep(Duration::from_secs(33)).await;

        let sent = socket.send(msg_data.clone(), addr.clone()).await;
        assert!(sent, "Failed to send message after mute expiration");

        sleep(Duration::from_secs(10)).await;

        {
            let received_messages = socket.recv.lock().await;
            assert!(!received_messages.is_empty(), "No messages received after mute expiration");
        } 

        socket.mute_address(addr.clone(), 30).await;
        socket.unmute_address(addr.clone()).await;
        {
            let muted = socket.muted_addresses.lock().await;
            assert!(!muted.contains_key(&addr_hash), "Address hash should be unmuted");
        } 

        let sent = socket.send(b"Unmuted message".to_vec(), addr).await;
        assert!(sent, "Failed to send message after unmuting");

        sleep(Duration::from_secs(10)).await;

        {
            let received_messages = socket.recv.lock().await;
            assert!(!received_messages.is_empty(), "No messages received after unmuting");
        } 
    }
}
