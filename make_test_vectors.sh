#!/bin/bash

GEN="cargo run --example test_vectors"
TEST_VECTORS=../test-vectors

cd reference-implementation

# Generate Markdown test vectors for each type individually
for kind in header aes128-ctr-hmac aes256-ctr-hmac sframe-rfc sframe-aes256-ctr-hmac;
do
  ${GEN} md ${kind} >${TEST_VECTORS}/${kind}.md
done

# Move RFC ones to where the RFC Markdown expects them to be
mv ${TEST_VECTORS}/aes128-ctr-hmac.md ${TEST_VECTORS}/aes-ctr-hmac.md
mv ${TEST_VECTORS}/sframe-rfc.md ${TEST_VECTORS}/sframe.md

# Generate JSON test vectors for the RFC capabilities
${GEN} json >${TEST_VECTORS}/test-vectors.json

# Generate JSON test vectors for AES-256-CTR-HMAC
${GEN} json aes256-ctr-hmac sframe-aes256-ctr-hmac >${TEST_VECTORS}/test-vectors-aes256.json
