//! Library of asynchronous Byzantine fault tolerant consensus known as "the
//! honey badger of BFT protocols" after a paper with the same title.
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
extern crate protobuf;
extern crate ring;
extern crate merkle;
extern crate futures;

mod errors;
mod proto;
mod task;

pub mod broadcast;
pub mod agreement;
