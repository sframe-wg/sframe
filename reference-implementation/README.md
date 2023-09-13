SFrame Reference Implementation
===============================

This directory contains a reference implementation of SFrame in Rust, using Rust
Crypto for the underlying cryptographic primitives.  This is the implementation
that is used to generate the test vectors in the RFC.

🚨🚨🚨 **WARNING: THIS IMPLEMENTATION MUST NOT BE USED IN PRODUCTION SOFTWARE.
It deliberately exposes secret values so that they can be presented in test
vectors.** 🚨🚨🚨


The unit tests in the individual source files validate that the reference
implementation interoperates with itself.  The code to generate test vectors is
in `examples/test_vectors.rs`.

```
# Build and run unit tests
> cargo build
> cargo test

# Generate test vectors (this will show the help message)
> cargo run --example test_vectors

# Update the test vectors in the document
> cd .. 
> ./make_test_vectors.sh
```
