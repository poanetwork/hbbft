//! Connection data and initiation routines.

use std::collections::HashSet;
use std::fmt::Debug;
use std::io::{Read, Write, BufReader};
use std::net::{TcpStream, TcpListener, SocketAddr};

#[derive(Debug)]
pub struct Connection {
    pub stream: TcpStream,
    pub reader: BufReader<TcpStream>,
}

impl Connection {
    pub fn new(stream: TcpStream) -> Self {
        Connection {
            // Create a read buffer of 1K bytes.
            reader: BufReader::with_capacity(1024, stream.try_clone().unwrap()),
            stream: stream
        }
    }
}

/// Connect this node to remote peers. A vector of successful connections is
/// returned.
pub fn make(bind_address: &SocketAddr,
            remote_addresses: &HashSet<SocketAddr>) -> Vec<Connection>
{
    // Connected remote nodes.
//    let mut connected: Vec<SocketAddr> = Vec::new();
    // Listen for incoming connections on a given TCP port.
    let bind_address = bind_address;
    let listener = TcpListener::bind(bind_address).unwrap();
    // Initialise initial connection states.
    let mut connections: Vec<Option<Connection>> =
        (0 .. remote_addresses.len())
        .into_iter()
        .map(|_| None)
        .collect();

    let here_str = format!("{}", bind_address);
    // Wait for all nodes with larger addresses to connect.
    for (n, &address) in remote_addresses.iter().enumerate() {
        let there_str = format!("{}", address);
        if here_str < there_str {
            connections[n] =
                match listener.accept() {
                    Ok((stream, _)) => {
                        info!("Connected to {}", there_str);
                        Some(Connection::new(stream))
                    },
                    Err(_) => None
                }
        }
    }

    // Try to connect to all nodes with smaller addresses.
    for (n, &address) in remote_addresses.iter().enumerate() {
        let there_str = format!("{}", address);
        if here_str > there_str {
            connections[n] =
                match TcpStream::connect(address) {
                    Ok(stream) => {
                        info!("Connected to {}", there_str);
                        Some(Connection::new(stream))
                    },
                    Err(_) => None
                }
        }
    }

    // remove Nones from connections
    connections.into_iter().filter_map(|c| c).collect()
}
