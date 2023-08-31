#!/usr/bin/env bash

mkdir ech
cp ./*.go ech
rm -rf http3_ech internal/handshake_ech internal/qtls_ech
cp -r http3 http3_ech
cp -r internal/handshake internal/handshake_ech
cp -r internal/qtls internal/qtls_ech
git add .
git commit -m "Add package copies for ECH"
