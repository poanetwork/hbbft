//! # HoneyBadgerBFT
//!
//! Library of asynchronous Byzantine fault tolerant consensus known as "the
//! honey badger of BFT protocols" after a paper with the same title.

#![feature(optin_builtin_traits)]
// TODO: Remove this once https://github.com/rust-lang-nursery/error-chain/issues/245 is resolved.
#![allow(renamed_and_removed_lints)]

extern crate bincode;
extern crate byteorder;
#[macro_use(Deref, DerefMut)]
extern crate derive_deref;
#[macro_use]
extern crate error_chain;
extern crate init_with;
#[macro_use]
extern crate log;
extern crate itertools;
extern crate merkle;
extern crate pairing;
#[cfg(feature = "serialization-protobuf")]
extern crate protobuf;
extern crate rand;
extern crate reed_solomon_erasure;
extern crate ring;
extern crate serde;
#[cfg(feature = "serialization-serde")]
#[macro_use]
extern crate serde_derive;

pub mod agreement;
pub mod broadcast;
pub mod common_coin;
pub mod common_subset;
pub mod crypto;
mod fmt;
pub mod honey_badger;
pub mod messaging;
#[cfg(feature = "serialization-protobuf")]
pub mod proto;
#[cfg(feature = "serialization-protobuf")]
pub mod proto_io;
