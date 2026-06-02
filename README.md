# Tinny

Tinny provides the `tinny` Rust library and the `can` command-line tool.

Use `can` to create and manage Tin Can files, which store password-encrypted
secrets in JSON. Tin applications can use the `tinny` library to access those
secrets when they are needed.

## Install

```sh
cargo install tinny
```

## Library

Add Tinny to an application as:

```toml
tinny = "0.1"
```

Then import it as:

```rust
use tinny::Can;
```
