Verify with:
```bash
# Check are all formatted as expected
cargo fmt -- --check
# Check does we have problems with clippy
cargo clippy --workspace --all-targets --all-features -- -D warnings
# Test, with all features
cargo test --all-targets --all-features
# Generate documentation
cargo doc --all-features --no-deps --open
```
