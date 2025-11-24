# Trace-ruler

*This repository contains the implementation and evaluation of trace ruler, an abuse-resistant source tracing scheme.*

## Overview

The implementation mainly consists of the following modules:
- [rust](rust):  Rust implementation of our scheme.
  - [apple-psi](rust/apple-psi): Implement Set Pre-Constraint Encryption.
  - [elgamal](rust/elgamal): Implement Elgamal Encryption.
  - [poksho](rust/poksho) & [zkcredential](rust/zkcredential): Modified Signal's implementation on ZK.
  - [rust-cuckoofilter](rust/rust-cuckoofilter): Modified Axiom's implementation on cuckoo filter.
  - [shamir](rust/shamir): Implement Shamir secret sharing.
  - [trace-ruler](rust/trace-ruler): Implement algorithms of trace ruler.
 
## Installation
The implementation is evaluated on a PC running Ubuntu OS, with Rust environment.

Install necessary packets:

```
sudo apt install curl build-essential gcc make
```

Switch Rust channel to nightly for benchmark:

```
rustup toolchain install nightly
rustup override set nightly
```


## Running
Run benchmark for runtime.
```
cargo bench trace-ruler
```

Run unit test
```
cargo test
```
