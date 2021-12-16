package xsyncmapfuzz

// generated via:
//     fzgen -chain -parallel github.com/thepudds/fzgen/examples/inputs/race-xsyncmap

import (
	"testing"

	xsyncmap "github.com/thepudds/fzgen/examples/inputs/race-xsync-map"
	"github.com/thepudds/fzgen/fuzzer"
)

func Fuzz_NewXSyncMap_Chain(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fz := fuzzer.NewFuzzer(data)

		target := xsyncmap.NewXSyncMap()

		steps := []fuzzer.Step{
			{
				Name: "Fuzz_XSyncMap_Delete",
				Func: func(key string) {
					target.Delete(key)
				},
			},
			{
				Name: "Fuzz_XSyncMap_Load",
				Func: func(key string) (int8, bool) {
					return target.Load(key)
				},
			},
			{
				Name: "Fuzz_XSyncMap_LoadAndDelete",
				Func: func(key string) (int8, bool) {
					return target.LoadAndDelete(key)
				},
			},
			{
				Name: "Fuzz_XSyncMap_LoadOrStore",
				Func: func(key string, value int8) (int8, bool) {
					return target.LoadOrStore(key, value)
				},
			},
			// skipping Fuzz_XSyncMap_Range because parameters include unsupported func or chan: func(key string, value interface{}) bool

			{
				Name: "Fuzz_XSyncMap_Store",
				Func: func(key string, value int8) {
					target.Store(key, value)
				},
			},
		}

		// Execute a specific chain of steps, with the count, sequence and arguments controlled by fz.Chain
		fz.Chain(steps, fuzzer.ChainOptParallel)
	})
}
