//! Networking controls of the consensus node.
use std::fmt::Debug;
use std::hash::Hash;
use std::collections::{HashMap, HashSet};
use std::marker::{Send, Sync};
use std::net::{TcpListener, SocketAddr};
use std::sync::{Arc, Mutex};
use std::sync::mpsc;
use spmc;
use crossbeam;

use broadcast;
use proto::Message;
use commst;

/// This is a structure to start a consensus node.
pub struct Node {
    /// Incoming connection socket.
    addr: SocketAddr,
    /// Sockets of remote nodes. TODO.
    remotes: Vec<SocketAddr>
}

impl Node {
    pub fn new(addr: SocketAddr, remotes: Vec<SocketAddr>) -> Self {
        Node {addr, remotes}
    }

    pub fn run<T: Clone + Debug + Eq + Hash + Send + Sync + From<Vec<u8>>>(&self)
    where Vec<u8>: From<T>
    {
        // Listen for incoming connections on a given TCP port.
        let listener = TcpListener::bind(&self.addr).unwrap();
        // Multicast channel from the manager task to comms tasks.
        let (stx, srx): (spmc::Sender<Message<T>>,
                         spmc::Receiver<Message<T>>) = spmc::channel();
        // Unicast channel from comms tasks to the manager task.
        let (mtx, mrx): (mpsc::Sender<Message<T>>,
                         mpsc::Receiver<Message<T>>) = mpsc::channel();

        // All spawned threads will have exited by the end of the scope.
        crossbeam::scope(|scope| {

            // Listen for incoming socket connections and start a comms task for
            // each new connection.
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        info!("New connection from {:?}",
                              stream.peer_addr().unwrap());
                        let tx = mtx.clone();
                        let rx = srx.clone();
                        scope.spawn(move || {
                            commst::CommsTask::new(tx, rx, stream).run();
                        });

                        // TODO: break when all the consensus participants have
                        // joined
                    }
                    Err(e) => {
                        warn!("Failed to connect: {}", e);
                    }
                }
            }

            // broadcast stage
            let (tx, rx) = (Arc::new(Mutex::new(stx)),
                            Arc::new(Mutex::new(mrx)));
            match broadcast::Stage::new(tx, rx).run() {
                Ok(v) => unimplemented!(),
                Err(e) => error!("Broadcast stage failed")
            }

            // TODO: other stages

        }); // end of thread scope
    }
}
