//! Example of a consensus node that uses the `hbbft::node::Node` struct for
//! running the distributed consensus state machine.
//#[macro_use]
extern crate log;
extern crate simple_logger;
extern crate docopt;
extern crate hbbft;

use hbbft::node::Node;
use docopt::Docopt;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::vec::Vec;

const VERSION: &str = "0.1.0";
const USAGE: &str = "
Consensus node example

Usage:
  consensus-node --bind-address=<host:port> [--value=VALUE] [--remote-address=<host:port>]...
  consensus-node (--help | -h)
  consensus-node --version
";

#[derive(Debug)]
struct Args {
    bind_address: SocketAddr,
    remote_addresses: HashSet<SocketAddr>,
    value: Option<Vec<u8>>,
}

fn parse_args() -> Args {
    let args = Docopt::new(USAGE)
        .unwrap_or_else(|e| e.exit())
        .version(Some(VERSION.to_owned()))
        .parse()
        .unwrap_or_else(|e| e.exit());
    Args {
        value: if args.get_count("--value") > 0 {
            Some(args.get_str("--value").as_bytes().to_vec())
        }
        else {
            None
        },
        bind_address: args.get_str("--bind-address").parse().unwrap(),
        remote_addresses: args.get_vec("--remote-address")
            .iter()
            .map(|s| s.parse().unwrap())
            .collect()
    }
}

pub fn main() {
    simple_logger::init_with_level(log::Level::Debug).unwrap();
    let args: Args = parse_args();
    println!("{:?}", args);
    let node = Node::new(args.bind_address, args.remote_addresses, args.value);
    node.run().expect("Node failed");
}
