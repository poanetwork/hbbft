//! # HoneyBadgerBFT
//!
//! Library of asynchronous Byzantine fault tolerant consensus known as "the
//! honey badger of BFT protocols" after a paper with the same title.

#![feature(optin_builtin_traits)]
#[macro_use]
extern crate log;
extern crate crossbeam;
extern crate crossbeam_channel;
extern crate merkle;
extern crate protobuf;
extern crate reed_solomon_erasure;
extern crate ring;

pub mod agreement;
pub mod broadcast;
pub mod common_subset;
pub mod messaging;
pub mod proto;
pub mod proto_io;
