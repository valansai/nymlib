# nymsocket



**`nymsocket`** interface for sending and receiving messages over the Nym mixnet, along with serialization utilities for handling diffrent of data structures like addresses and messages. Key components include:



- **SockAddr**: Enum for Nym addresses (`NymAddress`), anonymous sender tags (`SenderTag`), or null addresses (`Null`).
- **SocketMessage**: Struct holds sender address parsed into ```SockAddr```, data payload, and timestamp.
- **Client**: Supports standard (persistent storage) and ephemeral (in-memory) Nym clients.
- **Socket**: Core interface for creating sockets in `Anonymous`, `Individual` modes, with features like message sending, listening, and metrics tracking.


---

##  Features

- Anonymous and individual messaging modes.
- Stale message detection and filtering based on timestamps.
- Metrics tracking for bytes sent and received.
- Persistent (`StandardClient`) and in-memory (`EphemeralClient`) client support.
- Thread-safe operations with `Arc<Mutex<...>>` for shared state.
- Custom serialization for addresses and messages.


For more techincal details about nymsocket see [DEVELOPERS.md](./DEVELOPERS.md) 

## Examples 

### Creating a Socket

``` rust 
use nymlib::nymsocket::{Socket, SocketMode};


/// Example: creating different types of sockets with Nym

//   Ephemeral socket in Individual mode
// - "Ephemeral" means the socket state is NOT stored on disk. Once disconnected, it is gone.
// - "Individual mode" means you identify as yourself, and others can message you directly
//   using your Nym address.
// - Useful for temporary sessions where persistence is not required.
let socket = Socket::new_ephemeral(SocketMode::Individual)
    .await
    .expect("Failed to create socket");

//   Ephemeral socket in Anonymous mode
// - Also temporary (not stored on disk).
// - "Anonymous mode" means messages are sent without directly revealing your Nym address.
// - Others cannot cant see your nym address, but they can communicate.
// - Useful for one-off anonymous interactions.
let socket = Socket::new_ephemeral(SocketMode::Anonymous)
    .await
    .expect("Failed to create socket");

//   Standard socket in Individual mode
// - "Standard" means the socket state is stored persistently (e.g. under the provided ID "test").
// - If you disconnect and reconnect with the same ID, your address remains consistent.
// - "Individual mode" means you use your Nym address, and others can always reach you
//   as long as you reconnect with the same ID.
// - Useful for long-lived identities.
let socket = Socket::new_standard("test", SocketMode::Individual)
    .await
    .expect("Failed to create socket");

//   Standard socket in Anonymous mode
// - Persistent socket (state stored with ID "test").
// - "Anonymous mode" means messages are sent without directly revealing your Nym address.
// - Even though the socket is persistent, the anonymity property remains the same.
// - Useful if you want recurring anonymous sessions without exposing your identity.
let socket = Socket::new_standard("test", SocketMode::Anonymous)
    .await
    .expect("Failed to create socket");


```

### Listening for Messages

Spawn a listener task to receive messages:
``` rust 
let mut listen_socket = socket.clone();
tokio::spawn(async move {
    listen_socket.listen().await;
});
```

### Sending a Message
``` rust 
let data = b"Hello over Nym!".to_vec();
let recipient = "CokKZeJDb2u4qJRWbptk9HcEJ8TJsjWmfoRaEUe1Ei8M.2bzg9gjoNfkF7rwrh5WK2fUXPpf4JqcS9iEvDmD9DCNw@7ntzmDZRvG4a1pnDBU4Bg1RiAmLwmqXV5sZGNw68Ce14";
socket.send(data, recipient).await;
```
### Receiving Messages

Access received messages from the socket's ```recv``` queue:
``` rust 
let received = socket.recv.lock().await.drain(..).collect::<Vec<_>>();
for msg in received {
    println!("Received from {:?}: {}", msg.from, String::from_utf8_lossy(&msg.data));
}
```
### Stale Message Filtering

Enable filtering of old messages:
``` rust 
socket.check_stale = true;
socket.stale_expiration_time = 300;  // Drop messages older than 5 minutes
```
### Disconnecting
``` rust 
socket.disconnect().await;
```
# Examples

## Basic Send/Receive Loop
``` rust 
#[tokio::main]
async fn main() {
    // Create an ephemeral socket in Individual mode for Nym mixnet communication.
    let mut socket = Socket::new_ephemeral(SocketMode::Individual)
        .await
        .expect("Failed to create socket");

    // Retrieve the socket's address for sending messages to itself.
    let self_addr = socket.getsockaddr().await.expect("Failed to get socket address");

    // Spawn a background task to listen for incoming messages.
    let mut listen_socket = socket.clone();
    tokio::spawn(async move {
        listen_socket.listen().await;
    });

    // Send a test message to the socket's own address.
    let data = b"Test message".to_vec();
    socket.send(data.clone(), self_addr.clone()).await;

    // Wait 15 seconds to allow message processing and reception.
    tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;

    // Collect received messages from the socket's receive buffer.
    let received_messages: Vec<_> = {
        let mut messages = socket.recv.lock().await;
        messages.drain(..).collect()
    };

    // Verify that exactly one message was received.
    assert_eq!(received_messages.len(), 1, "Expected exactly one message");

    // Extract the first received message for validation.
    let msg = received_messages[0].clone();

    // Validate the message payload matches the sent data.
    assert_eq!(msg.data, data, "Received message data does not match sent data");

    // Verify the sender address matches the socket's own address.
    assert_eq!(msg.from, self_addr, "Sender address does not match expected address");

    // Confirm the message originates from a socket in Individual mode.
    assert!(msg.is_from_individual(), "Message should be from Individual mode");

    // Note: To test a message from Anonymous mode, a separate socket in Anonymous mode
    // would need to be created and used to send a message. The following assertion is
    // commented out as it would fail with the current setup.
    // assert!(!msg.is_from_anonymous(), "Message should be from Anonymous mode");

    // Send a reply to the message's sender using its `from` address.
    let reply = socket.send(b"Hey".to_vec(), msg.from).await;

    // Verify the reply was sent successfully.
    assert!(reply, "Failed to send reply");
}
```

