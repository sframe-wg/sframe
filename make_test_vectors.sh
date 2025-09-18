#!/bin/bash

TEST_VECTORS=test-vectors

cd reference-implementation

for kind in header aes-ctr-hmac aes256-ctr-hmac sframe;
do
  cargo run --example test_vectors md ${kind} >../test-vectors/${kind}.md
done

cargo run --example test_vectors json >../test-vectors/test-vectors.json
