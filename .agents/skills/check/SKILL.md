---
name: check
description: Always use this skill to verify a change locally
---

# Verifying a Change

Keep this file in sync with CI workflows.

Run these by default:

```
cargo fmt --all
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --doc
cargo doc --all-features --no-deps --locked
```

## New crates

A new crate must be referenced in the toplevel `Cargo.toml` as well as `release-plz.toml`.
