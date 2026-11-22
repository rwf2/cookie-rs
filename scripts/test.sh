#!/bin/bash

set -e

cargo build --verbose

cargo test --verbose --no-default-features --features percent-encode
cargo test --verbose --no-default-features --features private
cargo test --verbose --no-default-features --features signed
cargo test --verbose --no-default-features --features secure
cargo test --verbose --no-default-features --features 'private,key-expansion'
cargo test --verbose --no-default-features --features 'signed,key-expansion'
cargo test --verbose --no-default-features --features 'secure,percent-encode'

cargo test --verbose
cargo test --verbose --no-default-features
cargo test --verbose --all-features

rustdoc --test README.md -L target
