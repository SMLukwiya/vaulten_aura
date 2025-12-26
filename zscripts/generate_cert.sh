#!/bin/sh

# generates a cert and key pairs for testing purposes
# root, intermediate and leaf
# the same name is used for cert and key file (passed when invoking the script)

RED="\033[31m"
GREEN="\033[32m"
BLUE="\033[34m"
RESET="\033[0m"

if [ -z $1 ]; then
    echo "${RED}Error${RESET}: pass cert base name"
    return
fi

out_dir=${PWD}/examples/config
base=$1

# root
root_key_file=${out_dir}/${base}_root_keypair.pem
root_csr_file=${out_dir}/${base}_root_csr.pem
root_cert_file=${out_dir}/${base}_root_cert.pem

openssl genpkey \
    -algorithm ED25519 \
    -out "$root_key_file"

openssl req \
    -new \
    -subj "/CN=Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -key "$root_key_file" \
    -out "$root_csr_file"

openssl x509 \
    -req \
    -in $root_csr_file \
    -copy_extensions copyall \
    -key "$root_key_file" \
    -days 365 \
    -out "$root_cert_file"

# intermediate
intermediate_key_file=${out_dir}/${base}_intermediate_keypair.pem
intermediate_csr_file=${out_dir}/${base}_intermediate_csr.pem
intermediate_cert_file=${out_dir}/${base}_intermediate_cert.pem

openssl genpkey \
    -algorithm ED25519 \
    -out "$intermediate_key_file"

openssl req \
    -new \
    -subj "/CN=Intermediate CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -key "$intermediate_key_file" \
    -out "$intermediate_csr_file"

openssl x509 \
    -req \
    -in $intermediate_csr_file \
    -copy_extensions copyall \
    -CA $root_cert_file \
    -CAkey $root_key_file \
    -days 365 \
    -out "$intermediate_cert_file"

# leaf
leaf_key_file=${out_dir}/${base}_leaf_keypair.pem
leaf_csr_file=${out_dir}/${base}_leaf_csr.pem
leaf_cert_file=${out_dir}/${base}_leaf_cert.pem

openssl genpkey \
    -algorithm ED25519 \
    -out "$leaf_key_file"

openssl req \
    -new \
    -subj "/CN=leaf CA" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -key "$leaf_key_file" \
    -out "$leaf_csr_file"

openssl x509 \
    -req \
    -in $leaf_csr_file \
    -copy_extensions copyall \
    -CA $intermediate_cert_file \
    -CAkey $intermediate_key_file \
    -days 365 \
    -out "$leaf_cert_file"