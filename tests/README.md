# Honey-badger tests

The `hbbft` crate comes with a toolkit for testing its various algorithms in simulated network environments.

## Old vs new

The old testing code can be found inside the `network` module and `.rs` files in the `tests` subdirectory that are not prefixed with `net_`. The newer networking code is contained inside the `net` module and the remaining `.rs` files.

## VirtualNet

Core of most tests is the `net::VirtualNet` struct, which simulates a network of nodes all running an instance of a distributed algorithm. Messages sent by these nodes are queued by the network. Every time the network is "cranked", a buffered message is delivered to its destination node and processed.

Virtual networks can also host an adversary that can affect faulty nodes (which are tracked automatically) or reorder queued messages.

To create a new network, one of the constructor methods must be used:

```rust
let num_faulty = 3;
let total = 10;

let mut net: VirtualNet<DynamicHoneyBadger<Vec<usize>, _>> =
    VirtualNet::new(0..total, num_faulty, |id, netinfo|
        DynamicHoneyBadger::builder().build(netinfo)
    ).expect("could not construct test network");
```

Algorithms that return a `Step` upon construction should use `new_with_step` instead.

### Sending input

`Input` can be sent to any node of the `VirtualNet` using the `send_input` method:

```rust
let input = ...;
let _step = net.send_input(123, input).expect("algorithm failed");
```

While the resulting step is returned, it needn't be processed to keep the network going, as its messages are automatically added to the queue.

Instead of targeting a node in particular, the same input can be sent to all nodes:

```rust
net.broadcast_input(input).expect("algorithm failed");
```

### Cranking the network

The network advances through the `crank()` function, on every call

0. the adversary is given a chance to re-order the message queue,
0. the next message in the queue is delivered to its destination node (if the node is non-faulty) or the adversary (if the node is faulty),
0. all messages from the resulting step are queued again,
0. and the resulting step (or error) is returned.

If there were no messages to begin with, `None` is returned instead.

Cranking can be done manually:

```rust
let step = net.crank()
              .expect("expected at least one messages")
              .expect("algorithm error");
```

For convenience, an iterator interface is also available:

```rust
for res in net {
    let (node_id, step) = res.expect("algorithm error");
    // ...
}
```

This has the drawback that access to the network is not available between cranks, since it will be borrowed inside the for-loop. A common workaround is using a while loop instead:

```rust
while let Some(res) = net.crank() {
    let (node_id, step) = res.expect("algorithm error");
    // `net` can still be mutable borrowed here.
}
```

### Tracing

TBW
