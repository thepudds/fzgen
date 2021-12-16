#!/bin/bash
set -x

export CGO_ENABLED=0

# fast.
go test ./fuzzer/...

# fast-ish.
go test ./gen -vet=off -run=ChainRace/race_exported_not_local_pkg
go test ./gen -vet=off -run=Types

# -end2end faster than ./gen.
go test . -vet=off -run=TestScript/return_reuse -end2end
go test . -vet=off -end2end

# slowest.
go test ./gen -vet=off

# wrap up with go vet. -vet=off seemed to help above, but should confirm.
go vet ./...
