// This deadlocks in puzpuzpuz/xsync.(*Map).Store -> puzpuzpuz/xsync.(*Map).doStore:
//    - reproduces at github.com/puzpuzpuz/xsync@v1.0.1-0.20210823092703-32778049b5f5
//    - fixed in github.com/puzpuzpuz/xsync@latest
//
// Deadlock repro extracted from:
//     fzgen -chain -parallel -pkg=github.com/thepudds/fzgen/examples/inputs/race-xsyncmap
//     gotip test -fuzz=. -race
//
// With the repro then emitted by:
//     export FZDEBUG=repro=1
//     gotip test -run=./170da805c157
//
// This is now a normal Go test file. Note: need to run this test multiple times, such as:
//     go test -count=10000 -timeout=10s
//
// Note: the original bug report was not via fzgen.
// This just looked like an interesting bug to try to reproduce with fzgen
// against a new sync.Map implementation that is being proposed
// to merge into the Go standard library (golang/go#47643).
package xsyncmaprepro

import (
	"sync"
	"testing"

	xsyncmap "github.com/thepudds/fzgen/examples/inputs/race-xsync-map"
)

func TestRepro_NewXSyncMap_Chain(t *testing.T) {

	target := xsyncmap.NewXSyncMap()

	Fuzz_XSyncMap_LoadOrStore := func(key string, value int8) (int8, bool) {
		return target.LoadOrStore(key, value)
	}

	Fuzz_XSyncMap_Store := func(key string, value int8) {
		target.Store(key, value)
	}

	// Execute next steps in parallel.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		Fuzz_XSyncMap_LoadOrStore(
			",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,",
			44,
		)
	}()
	go func() {
		defer wg.Done()
		Fuzz_XSyncMap_LoadOrStore(
			",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,",
			44,
		)
	}()
	wg.Wait()

	// Resume sequential execution.
	Fuzz_XSyncMap_LoadOrStore(
		",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,",
		44,
	)
	Fuzz_XSyncMap_Store(
		",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,",
		44,
	)
	Fuzz_XSyncMap_Store(
		",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,",
		44,
	)
	Fuzz_XSyncMap_Store(
		",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,",
		44,
	)
	Fuzz_XSyncMap_Store(
		",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,",
		44,
	)
	Fuzz_XSyncMap_Store(
		",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,",
		44,
	)

}
