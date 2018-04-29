//! Network simulator for testing without message serialisation. Socket
//! connections between nodes are simulated using
//! `crossbeam_channel::unbounded`.

extern crate crossbeam_channel;
extern crate log;

use crossbeam_channel::{Sender, Receiver, unbounded};

pub struct NetSim<Message: Clone + Send + Sync> {
    /// The number of simulated nodes.
    num_nodes: usize,
    /// All TX handles
    txs: Vec<Sender<Message>>,
    /// All RX handles
    rxs: Vec<Receiver<Message>>,
}

impl<Message: Clone + Send + Sync> NetSim<Message> {
    pub fn new(num_nodes: usize) -> Self {
        assert!(num_nodes > 1);
        // All channels of a totally connected network of size `num_nodes`.
        let channels: Vec<(Sender<Message>, Receiver<Message>)> =
            (0 .. num_nodes * num_nodes)
            .map(|_| unbounded())
            .collect();
        let txs = channels.iter()
            .map(|&(ref tx, _)| tx.to_owned())
            .collect();
        let rxs = channels.iter()
            .map(|&(_, ref rx)| rx.to_owned())
            .collect();
        NetSim {
            num_nodes,
            txs,
            rxs
        }
    }

    /// The TX side of a channel from node `src` to node `dst`.
    pub fn tx(&self, src: usize, dst: usize) -> Sender<Message> {
        assert!(src < self.num_nodes);
        assert!(dst < self.num_nodes);

        self.txs[src * self.num_nodes + dst].clone()
    }

    /// The RX side of a channel from node `src` to node `dst`.
    pub fn rx(&self, src: usize, dst: usize) -> Receiver<Message> {
        assert!(src < self.num_nodes);
        assert!(dst < self.num_nodes);

        self.rxs[src * self.num_nodes + dst].clone()
    }
}
