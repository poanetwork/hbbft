//! # HoneyBadgerBFT
//!
//! Library of asynchronous Byzantine fault tolerant consensus known as "the
//! honey badger of BFT protocols" after a paper with the same title.

#![feature(optin_builtin_traits)]

extern crate bincode;
extern crate itertools;
#[macro_use]
extern crate log;
extern crate merkle;
extern crate protobuf;
extern crate reed_solomon_erasure;
extern crate ring;
extern crate serde;

pub mod agreement;
pub mod broadcast;
pub mod common_subset;
pub mod honey_badger;
pub mod messaging;
pub mod proto;
pub mod proto_io;
