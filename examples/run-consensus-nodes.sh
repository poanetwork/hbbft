#! /bin/bash

export RUST_LOG=hbbft=debug

cargo build --example consensus-node
cargo run --example consensus-node -- --bind-address=127.0.0.1:5000 --remote-address=127.0.0.1:5001 --remote-address=127.0.0.1:5002 --remote-address=127.0.0.1:5003 --value=Foo &
sleep 1
cargo run --example consensus-node -- --bind-address=127.0.0.1:5001 --remote-address=127.0.0.1:5000 --remote-address=127.0.0.1:5002 --remote-address=127.0.0.1:5003 &
sleep 1
cargo run --example consensus-node -- --bind-address=127.0.0.1:5002 --remote-address=127.0.0.1:5000 --remote-address=127.0.0.1:5001 --remote-address=127.0.0.1:5003 &
sleep 1
cargo run --example consensus-node -- --bind-address=127.0.0.1:5003 --remote-address=127.0.0.1:5000 --remote-address=127.0.0.1:5001 --remote-address=127.0.0.1:5002 &
wait
