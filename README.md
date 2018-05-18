[![Build Status](https://travis-ci.com/poanetwork/hbbft.svg?branch=master)](https://travis-ci.com/poanetwork/hbbft) 
[![Gitter](https://badges.gitter.im/poanetwork/hbbft.svg)](https://gitter.im/poanetwork/hbbft?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

# About

An implementation of the paper
["Honey Badger of BFT Protocols"](https://eprint.iacr.org/2016/199.pdf)
in Rust. This is a modular library of consensus. There are
[examples](./examples/README.md) illustrating the use of this algorithm.

**This is work in progress.** Parts of the algorithm are still missing
or incomplete.

An example is included to run a simulation of a network:

    $ cargo run --example simulation -- --nodes 10 --faulty 1 --txs 1000 --batch 100

# Building

You can build `hbbft` using cargo:

    $ cargo build [--release]
