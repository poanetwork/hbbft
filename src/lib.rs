//! # HoneyBadgerBFT
//!
//! Library of asynchronous Byzantine fault tolerant consensus known as "the
//! honey badger of BFT protocols" after a paper with the same title.

#![feature(optin_builtin_traits)]

extern crate bincode;
#[macro_use(Deref, DerefMut)]
extern crate derive_deref;
#[macro_use]
extern crate log;
extern crate itertools;
extern crate merkle;
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
pub mod common_subset;
mod fmt;
pub mod honey_badger;
pub mod messaging;
#[cfg(feature = "serialization-protobuf")]
pub mod proto;
#[cfg(feature = "serialization-protobuf")]
pub mod proto_io;
