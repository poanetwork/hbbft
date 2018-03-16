//! Networking controls of the consensus node.
use std::sync::mpsc;
use std::fmt::Debug;
use std::collections::{HashMap, HashSet};
use std::net::{TcpStream, TcpListener, SocketAddr};
use broadcast::*;

/// This is a structure to start a consensus node.
pub struct Node {
    /// Incoming connection socket.
    addr: SocketAddr,
    /// Connection sockets of remote nodes. TODO.
    remotes: Vec<SocketAddr>
}

impl Node {
    pub fn new(addr: SocketAddr, remotes: Vec<SocketAddr>) -> Self {
        Node {addr, remotes}
    }

    pub fn run(&self) {
        // Listen for incoming connections on a given TCP port.
        let listener = TcpListener::bind(&self.addr).unwrap();

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    info!("New connection from {:?}",
                          stream.peer_addr().unwrap());

                    // TODO: spawn a thread for the connected socket
                }
                Err(e) => {
                    warn!("Failed to connect: {}", e);
                }
            }
        }
    }
}
