#!/usr/bin/env bash
# Builds PGPBridge (Go, wraps GopenPGP) into Pgpbridge.xcframework for macOS.
# Requires: Go (brew install go) and Xcode. Fetches pinned modules (go.sum).
set -euo pipefail
cd "$(dirname "$0")/../PGPBridge"
export GOFLAGS=-mod=mod
# gomobile locates gobind via PATH; make sure Go-installed tools are found.
export PATH="$(go env GOPATH)/bin:$PATH"
# Keep the Go runtime compatible with macOS 14 (requirement).
export MACOSX_DEPLOYMENT_TARGET=14.0
export CGO_CFLAGS="-mmacosx-version-min=14.0"
export CGO_LDFLAGS="-mmacosx-version-min=14.0"
go mod tidy
go test ./...
go get golang.org/x/mobile/bind
# Install the tools at the exact version pinned in go.mod / go.sum.
go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
GM="$(go env GOPATH)/bin/gomobile"
"$GM" init
rm -rf ../Pgpbridge.xcframework
"$GM" bind -target=macos -o ../Pgpbridge.xcframework ./pgpbridge
echo "Built Pgpbridge.xcframework"
