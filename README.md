# Honey Badger Byzantine Fault Tolerant (BFT) consensus algorithm

[![Build Status](https://travis-ci.com/poanetwork/hbbft.svg?branch=master)](https://travis-ci.com/poanetwork/hbbft) 
[![Gitter](https://badges.gitter.im/poanetwork/hbbft.svg)](https://gitter.im/poanetwork/hbbft?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

Welcome to a [Rust](https://www.rust-lang.org/en-US/) library of the Honey Badger Byzantine Fault Tolerant (BFT) consensus algorithm. The research and protocols for this algorithm are explained in detail in "[The Honey Badger of BFT Protocols](https://eprint.iacr.org/2016/199.pdf)" by Miller et al., 2016.

Our implementation modifies the protocols described in the paper in several ways:
*  We use a [pairing elliptic curve library](https://github.com/ebfull/pairing) to implement pairing-based cryptography rather than Gap Diffie-Hellman groups. 
* We add a `Terminate` message to the Binary Agreement algorithm. Termination occurs following output, preventing the algorithm from running (or staying in memory) indefinitely. ([#53](https://github.com/poanetwork/hbbft/issues/55))
*  We add a `Conf` message to the Binary Agreement algorithm. An additional message phase prevents an attack if an adversary controls a network scheduler and a node. ([#37](https://github.com/poanetwork/hbbft/issues/37))
*  We return additional information from the Subset and Honey Badger algorithms that specifies which node input which data. This allows for identification of potentially malicious nodes.
* We run a Distributed Key Generation (DKG) protocol which does not require a trusted dealer; nodes collectively generate a secret key. This addresses the problem of single point of failure. See [Distributed Key Generation in the Wild](https://eprint.iacr.org/2012/377.pdf).

Following is an overview of HoneyBadger BFT and [basic instructions for getting started](#getting-started). 

_**Note:** This library is a work in progress and parts of the algorithm are still in development._

## What is Honey Badger?
The Honey Badger consensus algorithm allows nodes in a distributed, potentially asynchronous environment to achieve agreement on transactions. The agreement process does not require a leader node, tolerates corrupted nodes, and makes progress in adverse network conditions. Example use cases are decentralized databases and blockchains.

Honey Badger is **Byzantine Fault Tolerant**. The protocol can reach consensus with a number of failed nodes f (including complete takeover by an attacker), as long as the total number N of nodes is greater than 3 * f.

Honey Badger is **asynchronous**.  It does not make timing assumptions about message delivery. An adversary can control network scheduling and delay messages without impacting consensus.

## How does it work?
Honey Badger is a modular library composed of several independent algorithms.  To reach consensus, Honey Badger proceeds in epochs. In each epoch, participating nodes broadcast a set of encrypted data transactions to one another and agree on the contents of those transactions. 

In an optimal networking environment, output includes data sent from each node. In an adverse environment, the output is an agreed upon subset of data. Either way, the resulting output contains a batch of transactions which is guaranteed to be consistent across all nodes.  

## Algorithms

All algorithms in the protocol are modular. Encryption to provide censorship resistance is currently in process for the top level Honey Badger algorithm.

### Algorithm naming conventions  

We have simplified algorithm naming conventions from the original paper.

|  Algorithm Name  | Original Name                    | 
| ---------------- | -------------------------------- | 
| Honey Badger     | HoneyBadgerBFT                   | 
| Subset           | Asynchronous Common Subset (ACS) |  
| Broadcast        | Reliable Broadcast (RBC)         |  
| Binary Agreement | Binary Byzantine Agreement (BBA) |  
| Coin             | Common Coin                      |  

### Algorithm short descriptions

- [ ] **[Honey Badger](https://github.com/poanetwork/hbbft/blob/master/src/honey_badger.rs):** The top level protocol proceeds in epochs using the protocols below. 

- [x] **[Subset](https://github.com/poanetwork/hbbft/blob/master/src/common_subset.rs):** Each node inputs data. The nodes agree on a subset of suggested data. 

- [x] **[Broadcast](https://github.com/poanetwork/hbbft/blob/master/src/broadcast.rs):** A proposer node inputs data and every node receives this output.

- [x] **[Binary Agreement](https://github.com/poanetwork/hbbft/blob/master/src/agreement/mod.rs):** Each node inputs a binary value. The nodes agree on a value that was input by at least one correct node. 

- [x] **[Coin](https://github.com/poanetwork/hbbft/blob/master/src/common_coin.rs):** A pseudorandom binary value used by the Binary Agreement protocol.


### Current TODOs

- [ ] Honey Badger encryption ([#41](https://github.com/poanetwork/hbbft/issues/41))

- [ ] Dynamic Honey Badger (adding and removing nodes in a live network environment) ([#47](https://github.com/poanetwork/hbbft/issues/47#issuecomment-394640406))

- [ ] Networking example to detail Honey Badger implementation

## Getting Started

This Rust library requires a distributed network environment to function. Details on network requirements TBD. 

_**Note:** Additional examples are currently in progress._

### Build

Requires `rust` and `cargo`: [installation instructions.](https://www.rust-lang.org/en-US/install.html)

```
$ cargo build [--release]
```

### Example Network Simulation

A basic example is included to run a network simulation.

```
$ cargo run --example simulation -h
```

## License

[![License: LGPL v3.0](https://img.shields.io/badge/License-LGPL%20v3-blue.svg)](https://www.gnu.org/licenses/lgpl-3.0)

This project is licensed under the GNU Lesser General Public License v3.0. See the [LICENSE](LICENSE) file for details.

## References

* [The Honey Badger of BFT Protocols](https://eprint.iacr.org/2016/199.pdf)

    $ cargo run --example simulation -- -h

* Other language implementations

  * [Python](https://github.com/amiller/HoneyBadgerBFT)

  * [Go](https://github.com/anthdm/hbbft)

  * [Erlang](https://github.com/helium/erlang-hbbft)

  * [Rust](https://github.com/rphmeier/honeybadger) - unfinished implementation
