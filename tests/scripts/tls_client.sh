#!/bin/sh

openssl s_client \
    -connect vaultenaura.local:8080 \
    -4 \
    -servername vaultenaura.local \
    -state \
    -alpn "http/2"
    # -debug \
    # -status \
    # -tls1_3
