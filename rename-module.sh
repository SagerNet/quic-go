#!/usr/bin/env bash

set -e -o pipefail

OLD_MODULE_NAME="github.com/quic-go/quic-go"
NEW_MODULE_NAME="github.com/sagernet/quic-go"

find . -name "*.go" -not -path "./.git/*" -print0 |
  xargs -0 perl -pi -e "s#\"\Q$OLD_MODULE_NAME\E(?=[\"/])#\"$NEW_MODULE_NAME#g"

perl -pi -e "s#^module \Q$OLD_MODULE_NAME\E\$#module $NEW_MODULE_NAME#" go.mod

go mod tidy

./reformat.sh

git commit -m "Rename module" -a
