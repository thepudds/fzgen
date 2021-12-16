// repro extracted from:
//     fzgen -chain -parallel -pkg=github.com/thepudds/fzgen/examples/inputs/race-xsyncmap
//
// Note: need to run this multiple times, such as:
//     go test -count=10000 -timeout=10s
//
// This deadlocks in puzpuzpuz/xsync.(*Map).Store -> puzpuzpuz/xsync.(*Map).doStore
package xsyncmaprepro

import (
	"sync"
	"testing"

	xsyncmap "github.com/thepudds/fzgen/examples/inputs/race-xsync-map"
)

func TestRepro2_NewXSyncMap_Chain(t *testing.T) {

        // target and steps copied from autofuzzchain_test.go

	target := xsyncmap.NewXSyncMap()

	Fuzz_XSyncMap_LoadOrStore := func(key string, value int8) (int8, bool) {
		return target.LoadOrStore(key, value)
	}

	Fuzz_XSyncMap_Store := func(key string, value int8) {
		target.Store(key, value)
	}

        // copied output from FZDEBUG=repro=1

        Fuzz_XSyncMap_LoadOrStore(
                "7210210080120#09ASSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS",
                83,
        )

        // Execute next steps in parallel.
        var wg sync.WaitGroup
        wg.Add(2)
        go func() {
                defer wg.Done()
                Fuzz_XSyncMap_LoadOrStore(
                        "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS",
                        83,
                )
        }()
        go func() {
                defer wg.Done()
                Fuzz_XSyncMap_Store(
                        "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS",
                        83,
                )
        }()
        wg.Wait()
        Fuzz_XSyncMap_Store(
                "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS",
                83,
        )
        Fuzz_XSyncMap_Store(
                "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS",
                83,
        )
        Fuzz_XSyncMap_Store(
                "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS",
                83,
        )
        Fuzz_XSyncMap_Store(
                "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS",
                83,
        )
        Fuzz_XSyncMap_Store(
                "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS",
                83,
        )
        Fuzz_XSyncMap_Store(
                "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS",
                83,
        )
        Fuzz_XSyncMap_Store(
                "SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS",
                83,
        )


}
