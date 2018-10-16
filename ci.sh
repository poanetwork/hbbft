#!/bin/sh

set -xe

export RUST_BACKTRACE=1
# Enables additional cpu-specific optimizations.
export RUSTFLAGS="-D warnings -C target-cpu=native"

# Currently, mlocking secrets is disabled due to secure memory limit issues.
export MLOCK_SECRETS=false

cargo clippy --all-targets -- --deny clippy
cargo clippy --all-features --all-targets -- --deny clippy
cargo fmt -- --check

# We only test with mocktography, to ensure tests aren't unreasonably long.
cargo test --features=use-insecure-test-only-mock-crypto --release
cargo doc
cargo deadlinks --dir target/doc/hbbft/
cargo audit
