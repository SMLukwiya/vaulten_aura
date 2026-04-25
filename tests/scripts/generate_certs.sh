#!/bin/sh

# generate certificate Authority to sign server cert
# Generate keypair
openssl genpkey \
    -algorithm ed25519 \
    -out ca_keypair.pem

# Generate CSR
openssl req \
    -new \
    -subj "/CN=Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -key ca_keypair.pem \
    -out ca_csr.pem

# Generate self-signed cert
openssl x509 \
    -req \
    -in ca_csr.pem \
    -copy_extensions copyall \
    -days 365 \
    -key ca_keypair.pem \
    -out ca_cert.pem

# Generate server keypair
openssl genpkey \
    -algorithm ed25519 \
    -out ngh2_server_keypair.pem

# Generate Certificate signing request
openssl req \
    -new \
    -subj "/CN=localhost" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -key ngh2_server_keypair.pem \
    -out ngh2_server_csr.pem

# Sign server cert with the Certificate Authority
openssl x509 \
    -req \
    -in ngh2_server_csr.pem \
    -copy_extensions copyall \
    -CA ca_cert.pem \
    -CAkey ca_keypair.pem \
    -days 365 \
    -out ngh2_server_cert.pem