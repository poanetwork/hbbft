[![Build Status](https://travis-ci.com/poanetwork/hbbft.svg?branch=master)](https://travis-ci.com/poanetwork/hbbft) 
[![Gitter](https://badges.gitter.im/poanetwork/hbbft.svg)](https://gitter.im/poanetwork/hbbft?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

# About

An implementation of the paper
["Honey Badger of BFT Protocols"](https://eprint.iacr.org/2016/199.pdf)
in Rust. This is a modular library of consensus. There are
[examples](./examples/README.md) illustrating the use of this algorithm.

# Requirements

You must have the Protocol Buffer compiler binary, `protoc`, located
somewhere in your `$PATH`. If you have not installed `protoc`, you can
download the binary and move it to `/usr/local/bin/protoc` using the 
following:

*Note* As of writing this, the latest stable release of `protoc` is
v3.5.1. You can check out what is the latest compiler version is
[here](https://github.com/google/protobuf/releases), and update the
following cURL url and zip-file name accordingly.

## Installing `protoc` on Debain/Ubuntu

    $ cd <some temporary working directory>
    $ sudo apt-get update
    $ sudo apt-get install -y unzip
    $ curl -OL https://github.com/google/protobuf/releases/download/v3.5.1/protoc-3.5.1-linux-x86_64.zip
    $ sudo unzip protoc-3.5.1-linux-x86_64.zip -d /usr/local bin/protoc
    $ sudo chown $(whoami) /usr/local/bin/protoc
    $ protoc --version
    $ rm protoc-3.5.1-linux-x86_64.zip

## Installing `protoc` on OSX

    $ cd <some temporary working directory>
    $ curl -OL https://github.com/google/protobuf/releases/download/v3.5.1/protoc-3.5.1-osx-x86_64.zip
    $ sudo unzip protoc-3.5.1-osx-x86_64.zip -d /usr/local bin/protoc
    $ protoc --version
    $ rm protoc-3.5.1-osx-x86_64.zip

# Building

Once you have verified that the `protoc` binary is in your `$PATH`, you can
build `hbbft` using cargo:

    $ cargo build [--release]
