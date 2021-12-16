package myrand

// if needed, fill in imports or run 'goimports'
import (
	"testing"
)

func Fuzz_PanicOn10(f *testing.F) {
	f.Fuzz(func(t *testing.T, a int) {
		PanicOn10(a)
	})
}

func Fuzz_PanicOn10000(f *testing.F) {
	f.Fuzz(func(t *testing.T, a int) {
		PanicOn10000(a)
	})
}

func Fuzz_PanicRandomly1000(f *testing.F) {
	f.Fuzz(func(t *testing.T, a int) {
		PanicRandomly1000(a)
	})
}

func Fuzz_PanicRandomly10000(f *testing.F) {
	f.Fuzz(func(t *testing.T, a int) {
		PanicRandomly10000(a)
	})
}

func Fuzz_PanicRandomly100000(f *testing.F) {
	f.Fuzz(func(t *testing.T, a int) {
		PanicRandomly100000(a)
	})
}
