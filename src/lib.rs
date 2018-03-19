//! Library of asynchronous Byzantine fault tolerant consensus known as "the
//! honey badger of BFT protocols" after a paper with the same title.
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;
extern crate protobuf;
extern crate ring;
extern crate merkle;
//extern crate futures;
extern crate spmc;

mod errors;
mod proto;
mod task;
mod commst;

pub mod node;
pub mod broadcast;
pub mod agreement;
