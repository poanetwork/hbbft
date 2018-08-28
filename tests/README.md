# Honey-badger tests

The `hbbft` crate comes with a toolkit for testing its various algorithms in simulated network environments.

## Old vs new

The old testing code can be found inside the `network` module and `.rs` files in the `tests` subdirectory that are not prefixed with `net_`. The newer networking code is contained inside the `net` module and the remaining `.rs` files.

The new implementation offers many advantages, such as better abstractions for adversaries, easier implementations influencing the message delivery order, better reporting of failed tests, packet recording and more convenience functions. The old tests continue to work, but will be migrated step-by-step to take advantage of the newer features.

## VirtualNet

Core of most tests is the `net::VirtualNet` struct, which simulates a network of nodes all running an instance of a distributed algorithm. Messages sent by these nodes are queued by the network. Every time the network is "cranked", a buffered message is delivered to its destination node and processed.

Virtual networks can also host an adversary that can affect faulty nodes (which are tracked automatically) or reorder queued messages.

Use the `NetBuilder` to create a new network:

```rust
// Create a network of 10 nodes, out of which 3 are faulty.
let mut net = NetBuilder::new(0..10)
    .num_faulty(3)
    .using(move |node| { DynamicHoneyBadger::builder().build(node.netinfo) })
    .build()
    .expect("could not construct test network");
```

Algorithms that return a `Step` upon construction should use `using_step` instead.

### Sending input

Send `Input` to any `VirtualNet` node using the `send_input` method:

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

1. the adversary is given a chance to re-order<sup>1</sup> the message queue,
1. the next message in the queue is delivered to its destination node (if the node is non-faulty) or the adversary (if the node is faulty),
1. all messages from the resulting step are queued,
1. and the resulting step (or error) is returned.

If there were no messages to begin with, `None` is returned instead.

<sup>1</sup>: Due to some implementation deficiencies it is possible for an adversary to mutate any part of VirtualNet (i.e. to change things beyond the scope of our adversary model). While this will be addressed in future versions, it is currently up to the test implementor to ensure that adversaries are not more powerful than they are supposed to be.

Cranking can be done manually:

```rust
let step = net.crank()
              .expect("expected at least one messages")
              .expect("algorithm error");

// Shorthand:
let step = net.crank_expect();
```

For convenience, an iterator interface is also available:

```rust
for res in net {
    let (node_id, step) = res.expect("algorithm error");
    // ...
}
```

This has the drawback that access to the network is not available between cranks, as it is borrowed inside the for-loop. A common workaround is using a while loop instead:

```rust
while let Some(res) = net.crank() {
    let (node_id, step) = res.expect("algorithm error");
    // `net` can still be mutable borrowed here.
}
```

### Inspecting the network

In addition to the returned `Step`s, the network and nodes can be queried through various methods: `VirtualNet::{nodes, faulty_nodes, correct_nodes, get, get_mut}`.

### Adversaries

Adversaries can be introduced through the `.adversary` method on the constructor and are expected to implement the `net::adversary::Adversary` trait. Generic adversaries are available in the same module, while algorithm-specific ones should live next to each test case.

```rust
// Missing example.
```

### Tracing

By default, all network tests write traces of every network message into logfiles, named `net-trace_*.txt` in the current working directory. Each log stores one message per line, in the format of `[SENDER] -> [RECEIVER]: MSG`.

This behavior can be controlled using the `HBBFT_TEST_TRACE` environment variable; if set and equal to `0` or `false`, this functionality is disabled. Tracing is enabled by default.

The `NetBuilder` allows hard-coding the trace setting, any value passed will override environment settings:

```rust
let net = NetBuilder(0..10)
  .trace(false)   // Never log network messages.
  // ...
```

### Checking outputs

As a convenience, all nodes capture any generated output during operation for inspection. The following code fragment demonstrates how to verify that all non-faulty nodes have output the same thing:

```rust
let first = net.correct_nodes().nth(0).unwrap().outputs();
assert!(net.nodes().all(|node| node.outputs() == first));

println!("End result: {:?}", first);
```
