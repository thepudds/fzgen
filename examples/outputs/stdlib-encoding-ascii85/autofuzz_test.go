package ascii85fuzz // rename if needed

// if needed, fill in imports or run 'goimports'
import (
	"encoding/ascii85"
	"io"
	"testing"

	"github.com/thepudds/fzgen/fuzzer"
)

func Fuzz_CorruptInputError_Error(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var e ascii85.CorruptInputError
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&e)

		e.Error()
	})
}

func Fuzz_Decode(f *testing.F) {
	f.Fuzz(func(t *testing.T, dst []byte, src []byte, flush bool) {
		ascii85.Decode(dst, src, flush)
	})
}

func Fuzz_Encode(f *testing.F) {
	f.Fuzz(func(t *testing.T, dst []byte, src []byte) {
		ascii85.Encode(dst, src)
	})
}

func Fuzz_MaxEncodedLen(f *testing.F) {
	f.Fuzz(func(t *testing.T, n int) {
		ascii85.MaxEncodedLen(n)
	})
}

func Fuzz_NewDecoder(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var r io.Reader
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&r)

		ascii85.NewDecoder(r)
	})
}

func Fuzz_NewEncoder(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var w io.Writer
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&w)

		ascii85.NewEncoder(w)
	})
}
