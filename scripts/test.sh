#!/bin/bash

set -e

cargo build --verbose

cargo test --verbose --features percent-encode
cargo test --verbose --features private
cargo test --verbose --features signed
cargo test --verbose --features secure
cargo test --verbose --features 'private,key-expansion'
cargo test --verbose --features 'signed,key-expansion'
cargo test --verbose --features 'secure,percent-encode'
cargo test --verbose --no-default-features --features chrono
cargo test --verbose --no-default-features --features 'chrono,private'
cargo test --verbose --no-default-features --features 'chrono,signed'
cargo test --verbose --no-default-features --features 'chrono,secure'
cargo test --verbose --no-default-features --features 'chrono,private,key-expansion'
cargo test --verbose --no-default-features --features 'chrono,signed,key-expansion'
cargo test --verbose --no-default-features --features 'chrono,secure,key-expansion'

if cargo test --verbose --features 'time,chrono' > /dev/null 2>&1; then
    echo 'features \"time\" and \"chrono\" cannot be enabled at the same time' >&2
    exit 1
fi

cargo test --verbose
cargo test --verbose --no-default-features

rustdoc --test README.md -L target
