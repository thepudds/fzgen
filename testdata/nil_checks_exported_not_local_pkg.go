package examplefuzz

import (
	"io"
	"testing"

	fuzzwrapexamples "github.com/thepudds/fzgen/examples/inputs/test-types"
	"github.com/thepudds/fzgen/fuzzer"
)

func Fuzz_NewTypesNilCheck_Chain(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fz := fuzzer.NewFuzzer(data)

		target := fuzzwrapexamples.NewTypesNilCheck()

		steps := []fuzzer.Step{
			{
				Name: "Fuzz_TypesNilCheck_Interface",
				Func: func(x1 io.Writer) {
					target.Interface(x1)
				},
			},
			{
				Name: "Fuzz_TypesNilCheck_Pointers",
				Func: func(x1 *int, x2 **int) {
					target.Pointers(x1, x2)
				},
			},
			{
				Name: "Fuzz_TypesNilCheck_WriteTo",
				Func: func(stream io.Writer) (int64, error) {
					return target.WriteTo(stream)
				},
			},
		}

		// Execute a specific chain of steps, with the count, sequence and arguments controlled by fz.Chain
		fz.Chain(steps)
	})
}
