package fuzzwrapexamples

// if needed, fill in imports or run 'goimports'
import (
	"io"
	"testing"

	"github.com/thepudds/fzgen/fuzzer"
)

func Fuzz_TypeExported_PointerExportedMethod(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var t1 *TypeExported
		var i int
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&t1, &i)
		if t1 == nil {
			return
		}

		t1.PointerExportedMethod(i)
	})
}

func Fuzz_TypeExported_NonPointerExportedMethod(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var t1 TypeExported
		var i int
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&t1, &i)

		t1.NonPointerExportedMethod(i)
	})
}

func Fuzz_FuncExported(f *testing.F) {
	f.Fuzz(func(t *testing.T, i int) {
		FuncExported(i)
	})
}

func Fuzz_FuncExportedUsesSupportedInterface(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var w io.Reader
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&w)

		FuncExportedUsesSupportedInterface(w)
	})
}

// skipping Fuzz_FuncExportedUsesUnsupportedInterface because parameters include unsupported interface: github.com/thepudds/fzgen/examples/inputs/test-exported.ExportedInterface
