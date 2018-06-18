[![Build Status](https://travis-ci.com/poanetwork/hbbft.svg?branch=master)](https://travis-ci.com/poanetwork/hbbft) 
[![Gitter](https://badges.gitter.im/poanetwork/hbbft.svg)](https://gitter.im/poanetwork/hbbft?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

# Honey Badger Byzantine Fault Tolerant (BFT) consensus algorithm

Welcome to a [Rust ](https://www.rust-lang.org/en-US/)library of the Honey Badger Byzantine Fault Tolerant (BFT) consensus algorithm. The research and protocols for this algorithm are explained in detail in "[The Honey Badger of BFT Protocols](https://eprint.iacr.org/2016/199.pdf)" by Miller et al.

This documentation is designed for Rust developers looking to use a resilient consensus algorithm on a distributed network. Following is an overview of HoneyBadger BFT and basic instructions for getting started. 

**Note:** This library is a work in progress and parts of the algorithm are still in development.

# What is Honey Badger?
The Honey Badger consensus algorithm allows nodes in a distributed, potentially asynchronous environment (decentralized databases and blockchains) to achieve agreement on transactions. The agreement process does not require a leader node, tolerates corrupted nodes, and makes progress in adverse network conditions. 

Honey Badger is **Byzantine Fault Tolerant**. The protocol can reach consensus with a number of failed nodes f (including complete takeover by an attacker), as long as the total number N of nodes is greater than 3 * f.

Honey Badger is **asynchronous**.  It does not make timing assumptions about message delivery. An adversary can control network scheduling and delay messages without impacting consensus.

# How does it work?
Honey Badger is a modular library composed of several independent algorithms.  To reach consensus, Honey Badger proceeds in epochs. In each epoch, participating nodes broadcast a set of encrypted data transactions to one another and agree on the contents of those transactions. 

In an optimal networking environment, output includes data sent from each node. In an adverse environment, the output is an agreed upon subset of data. Either way, the resulting output contains a batch of transactions which is guaranteed to be consistent across all nodes.  

## Algorithms

All algorithms in the protocol are modular and usable. Encryption to provide censorship resistance is currently in process for the top level Honey Badger algorithm.

- [ ] **[Honey Badger](https://github.com/poanetwork/hbbft/blob/master/src/honey_badger.rs):** The top level protocol proceeds in epochs using the protocols below. 

- [x] **[Subset](https://github.com/poanetwork/hbbft/blob/master/src/common_subset.rs):** Each node inputs data. The nodes agree on a subset of suggested data. 

- [x] **[Broadcast](https://github.com/poanetwork/hbbft/blob/master/src/broadcast.rs):** A proposer node inputs data and every node receives this output.

- [x] **[Binary Agreement](https://github.com/poanetwork/hbbft/blob/master/src/agreement/mod.rs):** Each node inputs a binary value. The nodes agree on a value that was input by at least one correct node. 

- [x] **[Coin](https://github.com/poanetwork/hbbft/blob/master/src/common_coin.rs):** A pseudorandom binary value used by the Binary Agreement protocol.


##    Current TODOs

- [ ] Honey Badger encryption

- [ ] Dynamic Honey Badger (adding and removing nodes in a live network environment)

- [ ] Networking example to detail Honey Badger implementation

# Getting Started

This Rust library requires a distributed network environment to function. Details on network requirements will be published in the [Rust package registry](https://crates.io/) once core algorithms are complete. 

**Note: Additional examples are currently in progress.**


## Build

```
$ cargo build [--release]
```

## Example Network Simulation

An example is included to run a simulation of a network using serialization-serde ([https://serde.rs/](https://serde.rs/)) to efficiently serialize and deserialize Rust data structures.

```
$ cargo run --example simulation --features=serialization-serde -- -h
```

# Contributing

Please look at [current issues](https://github.com/poanetwork/hbbft/issues) and read [CONTRIBUTING.md](CONTRIBUTING.md) for contribution and pull request protocol.

# License

[![License: LGPL v3]([https://img.shields.io/badge/License-LGPL%20v3-blue.svg](https://img.shields.io/badge/License-LGPL%20v3-blue.svg))]([https://www.gnu.org/licenses/lgpl-3.0](https://www.gnu.org/licenses/lgpl-3.0))

This project is licensed under the GNU Lesser General Public License v3.0. See the [LICENSE](LICENSE) file for details.

# References

* [The Honey Badger of BFT Protocols](https://eprint.iacr.org/2016/199.pdf)

* [Honey Badger Video](https://www.youtube.com/watch?v=Qone4j1hCt8)

* Other language implementations

  * [Go ](https://github.com/anthdm/hbbft)

  * [Erlang](https://github.com/helium/erlang-hbbft)
