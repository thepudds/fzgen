package examplefuzz

import (
	"testing"

	"github.com/thepudds/fzgen/fuzzer"
)

func Fuzz_NewMySafeMap_Chain(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fz := fuzzer.NewFuzzer(data)

		target := NewMySafeMap()

		steps := []fuzzer.Step{
			{
				Name: "Fuzz_MySafeMap_Load",
				Func: func(key [16]byte) *Request {
					return target.Load(key)
				},
			},
			{
				Name: "Fuzz_MySafeMap_Store",
				Func: func(key [16]byte, req *Request) {
					target.Store(key, req)
				},
			},
		}

		// Execute a specific chain of steps, with the count, sequence and arguments controlled by fz.Chain
		fz.Chain(steps)
	})
}
