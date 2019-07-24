# Honey Badger Byzantine Fault Tolerant (BFT) consensus algorithm

[![crates.io](https://img.shields.io/crates/v/hbbft.svg)](https://crates.io/crates/hbbft)
[![Documentation](https://docs.rs/hbbft/badge.svg)](https://docs.rs/hbbft)
[![Build Status](https://travis-ci.org/poanetwork/hbbft.svg?branch=master)](https://travis-ci.org/poanetwork/hbbft)
[![Gitter](https://badges.gitter.im/poanetwork/hbbft.svg)](https://gitter.im/poanetwork/hbbft?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

Welcome to a [Rust](https://www.rust-lang.org/en-US/) library of the Honey Badger Byzantine Fault Tolerant (BFT) consensus algorithm. The research and protocols for this algorithm are explained in detail in "[The Honey Badger of BFT Protocols](https://eprint.iacr.org/2016/199.pdf)" by Miller et al., 2016.

An [official security audit](https://github.com/poanetwork/wiki/blob/master/assets/pdf/hbbft-audit-report.pdf) has been completed on `hbbft` by [Jean-Philippe Aumasson](https://aumasson.jp/).

Following is an overview of HoneyBadger BFT and [basic instructions for getting started](#getting-started).

_**Note:** This library is a work in progress and parts of the algorithm are still in development._

## What is Honey Badger?

The Honey Badger consensus algorithm allows nodes in a distributed, potentially asynchronous environment to achieve agreement on transactions. The agreement process does not require a leader node, tolerates corrupted nodes, and makes progress in adverse network conditions. Example use cases are decentralized databases and blockchains.

Honey Badger is **Byzantine Fault Tolerant**. The protocol can reach consensus with a number of failed nodes f (including complete takeover by an attacker), as long as the total number N of nodes is greater than 3 \* f.

Honey Badger is **asynchronous**.  It does not make timing assumptions about message delivery. An adversary can control network scheduling and delay messages without impacting consensus.

## How does it work?

Honey Badger is a modular library composed of several independent algorithms.  To reach consensus, Honey Badger proceeds in epochs. In each epoch, participating nodes broadcast a set of encrypted data transactions to one another and agree on the contents of those transactions.

In an optimal networking environment, output includes data sent from each node. In an adverse environment, the output is an agreed upon subset of data. Either way, the resulting output contains a batch of transactions which is guaranteed to be consistent across all nodes.

In addition to **validators**, the algorithms support **observers**: These don't actively participate, and don't need to be trusted, but they receive the output as well, and are able to verify it under the assumption that more than two thirds of the validators are correct.

Please see the following posts for more details:

-   [POA Network: Building Honey Badger BFT](https://medium.com/poa-network/poa-network-building-honey-badger-bft-c953afa4d926)

-   [POA Network: How Honey Badger BFT Consensus Works](https://medium.com/poa-network/poa-network-how-honey-badger-bft-consensus-works-4b16c0f1ff94)

-   [POA Network: Honey Badger BFT and Threshold Cryptography](https://medium.com/poa-network/poa-network-honey-badger-bft-and-threshold-cryptography-c43e10fadd87)

## Algorithms

-   **[Honey Badger](src/honey_badger/honey_badger.rs):** Each node inputs transactions. The protocol outputs a sequence of batches of transactions.

-   **[Dynamic Honey Badger](src/dynamic_honey_badger/dynamic_honey_badger.rs):** A modified Honey Badger where nodes can dynamically add and remove other nodes to/from the network.

-   **[Queueing Honey Badger](src/queueing_honey_badger/mod.rs):** Works exactly like Dynamic Honey Badger, but includes a built in transaction queue.

-   **[Subset](src/subset/subset.rs):** Each node inputs data. The nodes agree on a subset of suggested data.

-   **[Broadcast](src/broadcast/broadcast.rs):** A proposer node inputs data and every node receives this output.

-   **[Binary Agreement](src/binary_agreement/binary_agreement.rs):** Each node inputs a binary value. The nodes agree on a value that was input by at least one correct node.

-   **[Threshold Sign](src/threshold_sign.rs):**
    Each node inputs the same data to be signed, and outputs the unique valid signature matching the public master key. It is used as a pseudorandom value in the Binary Agreement protocol.

-   **[Threshold Decryption](src/threshold_decrypt.rs):**
    Each node inputs the same ciphertext, encrypted to the public master key, and outputs the decrypted data.

-   **[Synchronous Key Generation](src/sync_key_gen.rs)** A dealerless algorithm that generates keys for threshold encryption and signing. Unlike the other algorithms, this one is _completely synchronous_ and should run on top of Honey Badger (or another consensus algorithm)

### External crates developed for this library

-   **[Threshold Crypto](https://github.com/poanetwork/threshold_crypto):** A threshold cryptosystem for collaborative message decryption and signature creation.

## Getting Started

This library requires a distributed network environment to function. Details on network requirements TBD.

_**Note:** Additional examples are currently in progress._

### Build

Requires Rust 1.36 or higher and `cargo`: [installation instructions.](https://www.rust-lang.org/en-US/install.html) The library is tested against the `stable` release channel.

    $ cargo build [--release]

### Testing

    $ cargo test --release

See the [tests README](tests/README.md) for more information on our testing toolkit.

### Example Network Simulation

A basic [example](examples/README.md) is included to run a network simulation.

    $ cargo run --example simulation --release

![Screenshot](assets/screenshot.png)

| Heading   | Definition                                                                                                                                                                                        |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Epoch     | Epoch number. In each epoch, transactions are processed in a batch by simulated nodes (default is 10 nodes) on a network. The batch is always output in one piece, with all transactions at once. |
| Min Time  | Time in simulated milliseconds until the first correct (i.e. not faulty) node outputs the batch.                                                                                                  |
| Max Time  | Time in simulated milliseconds until the last correct node outputs the batch.                                                                                                                     |
| Txs       | Number of transactions processed in the epoch.                                                                                                                                                    |
| Msgs/Node | Average number of messages handled by a node. The counter is cumulative and includes the number of messages handled in the current epoch and all previous epochs.                                 |
| Size/Node | Average message size (in converted bytes) handled by a node. This is cumulative and includes message size for the current epoch and all previous epochs.                                          |

#### Options

Set different parameters to simulate different transaction and network conditions.

| Flag                    | Description                                                  |
| ----------------------- | ------------------------------------------------------------ |
| `-h, --help`            | Show help options                                            |
| `--version`             | Show the version of hbbft                                    |
| `-n <n>, --nodes <n>`   | The total number of nodes [default: 10]                      |
| `-f <f>, --faulty <f>`  | The number of faulty nodes [default: 0]                      |
| `-t <txs>, --txs <txs>` | The number of transactions to process [default: 1000]        |
| `-b <b>, --batch <b>`   | The batch size, i.e. txs per epoch [default: 100]            |
| `-l <lag>, --lag <lag>` | The network lag between sending and receiving [default: 100] |
| `--bw <bw>`             | The bandwidth, in kbit/s [default: 2000]                     |
| `--cpu <cpu>`           | The CPU speed, in percent of this machine's [default: 100]   |
| `--tx-size <size>`      | The size of a transaction, in bytes [default: 10]            |

**Examples:**

```bash
# view options
$ cargo run --example simulation --release -- -h

# simulate a network with 12 nodes, 2 of which are faulty
$ cargo run --example simulation --release -- -n 12 -f 2

# increase batch size to 500 transactions per epoch
$ cargo run --example simulation --release -- -b 500
```

## Protocol Modifications

Our implementation modifies the protocols described in "[The Honey Badger of BFT Protocols](https://eprint.iacr.org/2016/199.pdf)" in several ways:

-   We use a [pairing elliptic curve library](https://github.com/ebfull/pairing) to implement pairing-based cryptography using a Barrento-Lynn-Scott (BLS12-381) curve.
-   We add a `Terminate` message to the Binary Agreement algorithm. Termination occurs following output, preventing the algorithm from running (or staying in memory) indefinitely. ([#53](https://github.com/poanetwork/hbbft/issues/55))
-   We add a `Conf` message to the Binary Agreement algorithm. An additional message phase prevents an attack if an adversary controls a network scheduler and a node. ([#37](https://github.com/poanetwork/hbbft/issues/37))
-   We return additional information from the Subset and Honey Badger algorithms that specifies which node input which data. This allows for identification of potentially malicious nodes.
-   We include a Distributed Key Generation (DKG) protocol which does not require a trusted dealer; nodes collectively generate a secret key. This addresses the problem of single point of failure. See [Distributed Key Generation in the Wild](https://eprint.iacr.org/2012/377.pdf).

### Algorithm naming conventions

We have simplified algorithm naming conventions from the original paper.

| Algorithm Name   | Original Name                                 |
| ---------------- | --------------------------------------------- |
| Honey Badger     | HoneyBadgerBFT                                |
| Subset           | Asynchronous Common Subset (ACS)              |
| Broadcast        | Reliable Broadcast (RBC)                      |
| Binary Agreement | Asynchronous Binary Byzantine Agreement (ABA) |

## References

-   [The Honey Badger of BFT Protocols](https://eprint.iacr.org/2016/199.pdf)

-   [Honey Badger Video](https://www.youtube.com/watch?v=Qone4j1hCt8)


-   Other language implementations

    -   [Python](https://github.com/initc3/HoneyBadgerBFT-Python)

    -   [Go](https://github.com/anthdm/hbbft)

    -   [Erlang](https://github.com/helium/erlang-hbbft)

    -   [Rust](https://github.com/rphmeier/honeybadger) - unfinished implementation

### Honey Badger Visualization

![Screenshot](assets/honey_badger_diagram.svg)

## Contributing

See the [CONTRIBUTING](CONTRIBUTING.md) document for contribution, testing and pull request protocol.

## License

Licensed under either of:

-   Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
-   MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
