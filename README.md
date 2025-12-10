# Trace-ruler

*This repository contains the implementation and evaluation of trace ruler, an abuse-resistant source tracing scheme for encrypted messaging systems.*

**NDSS 2026:** Abuse Resistant Traceability with Minimal Trust for Encrypted Messaging Systems [[conference](https://dx.doi.org/10.14722/ndss.2026.240456)] [[eprint](https://eprint.iacr.org/2025/2187)]

## Overview

The implementation mainly consists of the following modules:
- [rust](rust):  Rust implementation of our scheme.
  - [apple-psi](rust/apple-psi): Implement Set Pre-Constraint Encryption.
  - [elgamal](rust/elgamal): Implement Elgamal Encryption.
  - [poksho](rust/poksho) & [zkcredential](rust/zkcredential): Modified Signal's implementation on ZKPs.
  - [rust-cuckoofilter](rust/rust-cuckoofilter): Modified Axiom's implementation on the cuckoo filter.
  - [shamir](rust/shamir): Implement Shamir secret sharing.
  - [trace-ruler](rust/trace-ruler): Implement algorithms of trace ruler.
 
## Installation
The implementation is evaluated on a PC running Ubuntu OS, with a Rust environment.

1. Install necessary packages:

```
sudo apt install curl build-essential gcc make
```

2. Switch Rust channel to nightly for benchmark:

```
rustup toolchain install nightly
rustup override set nightly
```


## Running
1. Run benchmark for runtime.
```
cargo bench trace-ruler
```

2. Run unit test
```
cargo test
```
