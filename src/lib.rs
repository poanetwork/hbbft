//! # HoneyBadgerBFT
//!
//! Library of asynchronous Byzantine fault tolerant consensus known as "the
//! honey badger of BFT protocols" after a paper with the same title.
//!
//! ## Example
//!
//! The following code could be run on host 192.168.1.1:
//!
//! ```rust
//! extern crate hbbft;
//!
//! use hbbft::node::Node;
//! use std::net::SocketAddr;
//! use std::vec::Vec;
//!
//! fn main() {
//!     let bind_address = "192.168.1.1:10001".parse().unwrap();
//!     let remote_addresses = vec!["192.168.1.2:10002".parse().unwrap(),
//!                                 "192.168.1.3:10003".parse().unwrap(),
//!                                 "192.168.1.4:10004".parse().unwrap(),
//!                                 "192.168.1.5:10005".parse().unwrap()];
//!     let value: &'static str = "Proposed value";
//!
//!     let result = Node::new(bind_address, remote_addresses, Some(value))
//!         .run();
//!     println!("Consensus result {:?}", result);
//! }
//! ```
//!
//! Similar code shall then run on hosts 192.168.1.2, 192.168.1.3, 192.168.1.4
//! and 192.168.1.5, with appropriate changes in `bind_address` and
//! `remote_addresses`. Each host has it's own optional broadcast `value`. If
//! the consensus `result` is not an error then every successfully terminated
//! consensus node will be the same `result`.

#![feature(optin_builtin_traits)]
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
extern crate protobuf;
extern crate ring;
extern crate merkle;
//extern crate futures;
extern crate spmc;
extern crate crossbeam;
extern crate reed_solomon_erasure;

mod connection;
mod errors;
mod proto;
mod task;
mod commst;

pub mod node;
pub mod broadcast;
pub mod agreement;
