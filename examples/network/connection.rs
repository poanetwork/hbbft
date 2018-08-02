//! Connection data and initiation routines.

use std::collections::{BTreeMap, HashSet};
use std::net::{SocketAddr, TcpListener, TcpStream};

#[derive(Debug)]
pub struct Connection {
    pub stream: TcpStream,
    pub node_str: String,
}

impl Connection {
    pub fn new(stream: TcpStream, node_str: String) -> Self {
        Connection { stream, node_str }
    }
}

/// Connect this node to remote peers. A vector of successful connections is returned, as well as
/// our own node ID.
pub fn make(
    bind_address: &SocketAddr,
    remote_addresses: &HashSet<SocketAddr>,
) -> (String, Vec<Connection>) {
    // Listen for incoming connections on a given TCP port.
    let bind_address = bind_address;
    let listener = TcpListener::bind(bind_address).expect("start listener");
    let here_str = format!("{}", bind_address);
    // Use a `BTreeMap` to make sure we all iterate in the same order.
    let remote_by_str: BTreeMap<String, _> = remote_addresses
        .iter()
        .map(|addr| (format!("{}", addr), addr))
        .filter(|(there_str, _)| *there_str != here_str)
        .collect();
    // Wait for all nodes with larger addresses to connect.
    let connections = remote_by_str
        .into_iter()
        .map(|(there_str, address)| {
            let tcp_conn = if here_str < there_str {
                listener.accept().expect("failed to connect").0
            } else {
                TcpStream::connect(address).expect("failed to connect")
            };
            Connection::new(tcp_conn, there_str.to_string())
        })
        .collect();
    (here_str, connections)
}
