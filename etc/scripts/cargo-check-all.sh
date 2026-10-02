#!/usr/bin/env bash

set -eux

cargo check --workspace --all-targets
target_dir="$(cargo metadata --format-version 1 --no-deps | jq --exit-status --raw-output '.target_directory')"
# Reuse compatible artifacts while resolving each fuzz workspace separately.
for manifest in gix-*/fuzz/Cargo.toml; do
    cargo check --manifest-path "$manifest" --all-targets --target-dir "$target_dir"
done
cargo check --no-default-features --features small
etc/scripts/check-gix-crates-without-hash-features.sh
etc/scripts/check-gix-crates-require-hash-features.sh
etc/scripts/check-gix-crates-do-not-default-hash-features.sh
etc/scripts/check-gix-crate-hash-feature-combinations.sh
cargo check -p legix-packetline --all-features 2>/dev/null
cargo check -p legix-transport --all-features 2>/dev/null
# Assure incompatible top-level feature combinations still fail, while legix-protocol supports both I/O modes together.
if cargo check --features lean-async 2>/dev/null; then
    printf '%s\n' 'Expected lean-async to conflict with the default blocking client features' >&2
    exit 1
fi
if cargo check -p legix-core --all-features --features legix/sha1 2>/dev/null; then
    printf '%s\n' 'Expected legix-core to reject enabling both client I/O modes' >&2
    exit 1
fi
cargo check -p legix-protocol --all-features
tree="$(cargo --color=never tree -p legix --no-default-features -e normal --prefix none --format '{p}')"
if printf '%s\n' "$tree" | grep -Eq '^legix-imara-diff(-01)? v'; then
    printf '%s\n' 'legix must not depend on legix-imara-diff without default features' >&2
    exit 1
fi
cargo --color=never tree -p legix --no-default-features -e normal -i legix-submodule \
    2>&1 >/dev/null | grep '^warning: nothing to print\>'
cargo --color=never tree -p legix --no-default-features -e normal -i legix-pathspec \
    2>&1 >/dev/null | grep '^warning: nothing to print\>'
cargo --color=never tree -p legix --no-default-features -e normal -i legix-filter \
    2>&1 >/dev/null | grep '^warning: nothing to print\>'
if cargo tree -p legix --no-default-features -i legix-credentials 2>/dev/null; then
    printf '%s\n' 'Expected legix-credentials to be absent without default features' >&2
    exit 1
fi
cargo check --no-default-features --features lean
cargo check --no-default-features --features lean-async
cargo check --no-default-features --features max
cargo check -p legix-core --features legix/sha1,blocking-client
cargo check -p legix-core --features legix/sha1,async-client
cargo check -p legix-pack --no-default-features --features sha1
cargo check -p legix-pack --no-default-features --features sha1,generate
cargo check -p legix-pack --no-default-features --features sha1,streaming-input
cargo check -p legix-hash --no-default-features --features sha1,bstr
cargo check -p legix-hash --all-features
cargo check -p legix-object --all-features
cargo check -p legix-attributes --features serde
cargo check -p legix-glob --features serde
cargo check -p legix-worktree --features serde 2>&1 >/dev/null | grep 'Please set either the `sha1` or the `sha256` feature flag'
cargo check -p legix-worktree --features sha1,serde
cargo check -p legix-worktree --no-default-features --features sha1
cargo check -p legix-actor --features serde
cargo check -p legix-date --features serde
cargo check -p legix-tempfile --features signals
cargo check -p legix-tempfile --features hp-hashmap
cargo check -p legix-pack --features serde 2>&1 >/dev/null | grep 'Please set either the `sha1` or the `sha256` feature flag'
cargo check -p legix-pack --features sha1,serde
cargo check -p legix-pack --features sha1,pack-cache-lru-static
cargo check -p legix-pack --features sha1,pack-cache-lru-dynamic
cargo check -p legix-pack --features sha1,object-cache-dynamic
cargo check -p legix-packetline --features blocking-io
cargo check -p legix-packetline --features async-io
cargo check -p legix-index --features serde 2>&1 >/dev/null | grep 'Please set either the `sha1` or the `sha256` feature flag'
cargo check -p legix-index --features sha1,serde
cargo check -p legix-credentials --features serde
cargo check -p legix-sec --features serde
cargo check -p legix-revision --features serde 2>&1 >/dev/null | grep 'Please set either the `sha1` or the `sha256` feature flag'
cargo check -p legix-revision --features sha1,serde
cargo check -p legix-revision --no-default-features --features sha1,describe
cargo check -p legix-mailmap --features serde
cargo check -p legix-url --all-features
cargo check -p legix-status --all-features
cargo check -p legix-features --all-features
cargo check -p legix-features --features parallel
cargo check -p legix-features --features fs-read-dir
cargo check -p legix-features --features progress
cargo check -p legix-features --features io-pipe
cargo check -p legix-features --features crc32
cargo check -p legix-features --features cache-efficiency-debug
cargo check -p legix-commitgraph --all-features
cargo check -p legix-config-value --all-features
cargo check -p legix-config --all-features
cargo check -p legix-diff --no-default-features 2>&1 >/dev/null | grep 'Please set either the `sha1` or the `sha256` feature flag'
cargo check -p legix-diff --no-default-features --features sha1
cargo check -p legix-transport --features blocking-client
cargo check -p legix-transport --features async-client
cargo check -p legix-transport --features async-client,async-std
cargo check -p legix-transport --features http-client
cargo check -p legix-transport --features http-client-curl
cargo check -p legix-transport --features http-client-reqwest
cargo check -p legix-protocol --features blocking-client 2>&1 >/dev/null | grep 'Please set either the `sha1` or the `sha256` feature flag'
cargo check -p legix-protocol --features sha1,blocking-client
cargo check -p legix-protocol --features sha1,async-client
cargo check -p legix --no-default-features --features sha1,async-network-client
cargo check -p legix --no-default-features --features sha1,async-network-client-async-std
cargo check -p legix --no-default-features --features sha1,blocking-network-client
cargo check -p legix --no-default-features --features sha1,blocking-http-transport-curl
cargo check -p legix --no-default-features --features sha1,blocking-http-transport-reqwest
cargo check -p legix --no-default-features --features max-performance --tests
cargo check -p legix --no-default-features --features max-performance-safe --tests
cargo check -p legix --no-default-features --features progress-tree --tests
cargo check -p legix --no-default-features --features blob-diff --tests
cargo check -p legix --no-default-features --features revision --tests
cargo check -p legix --no-default-features --features revparse-regex --tests
cargo check -p legix --no-default-features --features mailmap --tests
cargo check -p legix --no-default-features --features excludes --tests
cargo check -p legix --no-default-features --features attributes --tests
cargo check -p legix --no-default-features --features worktree-mutation --tests
cargo check -p legix --no-default-features --features credentials --tests
cargo check -p legix --no-default-features --features index --tests
cargo check -p legix --no-default-features --features interrupt --tests
cargo check -p legix --no-default-features --features blame --tests
cargo check -p legix --no-default-features --features sha1
cargo check -p legix --no-default-features --features sha1,sha256
cargo check -p legix --no-default-features --features sha256
cargo check -p legix --no-default-features 2>&1 >/dev/null | grep 'Please set either the `sha1` or the `sha256` feature flag'
cargo check -p legix-odb --features serde 2>&1 >/dev/null | grep 'Please set either the `sha1` or the `sha256` feature flag'
cargo check -p legix-odb --features sha1,serde
cargo check --no-default-features --features max-control,sha1
