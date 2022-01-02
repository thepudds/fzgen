package examplefuzz

// if needed, fill in imports or run 'goimports'
import (
	"context"
	"io"
	"testing"
	"unsafe"

	fuzzwrapexamples "github.com/thepudds/fzgen/examples/inputs/test-types"
	"github.com/thepudds/fzgen/fuzzer"
)

func Fuzz_TypesNilCheck_Interface(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var x1 io.Writer
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&x1)

		n := fuzzwrapexamples.NewTypesNilCheck()
		n.Interface(x1)
	})
}

func Fuzz_TypesNilCheck_Pointers(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var x1 *int
		var x2 **int
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&x1, &x2)
		if x1 == nil || x2 == nil {
			return
		}

		n := fuzzwrapexamples.NewTypesNilCheck()
		n.Pointers(x1, x2)
	})
}

func Fuzz_TypesNilCheck_WriteTo(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var stream io.Writer
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&stream)

		n := fuzzwrapexamples.NewTypesNilCheck()
		n.WriteTo(stream)
	})
}

func Fuzz_Std_ListenPacket(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var _x1 fuzzwrapexamples.Std
		var ctx context.Context
		var network string
		var address string
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&_x1, &ctx, &network, &address)

		_x1.ListenPacket(ctx, network, address)
	})
}

// skipping Fuzz_Discard because parameters include unsupported interface: []interface{}

func Fuzz_Discard2(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var _x1 string
		var _x2 []int
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&_x1, &_x2)

		fuzzwrapexamples.Discard2(_x1, _x2...)
	})
}

func Fuzz_InterfacesFullList(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var x1 io.Writer
		var x2 io.Reader
		var x3 io.ReaderAt
		var x4 io.WriterTo
		var x5 io.Seeker
		var x6 io.ByteScanner
		var x7 io.RuneScanner
		var x8 io.ReadSeeker
		var x9 io.ByteReader
		var x10 io.RuneReader
		var x11 io.ByteWriter
		var x12 io.ReadWriter
		var x13 io.ReaderFrom
		var x14 io.StringWriter
		var x15 io.Closer
		var x16 io.ReadCloser
		var x17 context.Context
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&x1, &x2, &x3, &x4, &x5, &x6, &x7, &x8, &x9, &x10, &x11, &x12, &x13, &x14, &x15, &x16, &x17)

		fuzzwrapexamples.InterfacesFullList(x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17)
	})
}

func Fuzz_InterfacesShortList(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var ctx context.Context
		var w io.Writer
		var r io.Reader
		var sw io.StringWriter
		var rc io.ReadCloser
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&ctx, &w, &r, &sw, &rc)

		fuzzwrapexamples.InterfacesShortList(ctx, w, r, sw, rc)
	})
}

// skipping Fuzz_InterfacesSkip because parameters include unsupported interface: net.Conn

func Fuzz_Short1(f *testing.F) {
	f.Fuzz(func(t *testing.T, x1 int) {
		fuzzwrapexamples.Short1(x1)
	})
}

func Fuzz_Short2(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var x1 *int
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&x1)
		if x1 == nil {
			return
		}

		fuzzwrapexamples.Short2(x1)
	})
}

func Fuzz_Short3(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var x1 **int
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&x1)
		if x1 == nil {
			return
		}

		fuzzwrapexamples.Short3(x1)
	})
}

func Fuzz_Short4(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var x1 fuzzwrapexamples.MyInt
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&x1)

		fuzzwrapexamples.Short4(x1)
	})
}

func Fuzz_Short5(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var x1 complex64
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&x1)

		fuzzwrapexamples.Short5(x1)
	})
}

func Fuzz_Short6(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var x1 complex128
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&x1)

		fuzzwrapexamples.Short6(x1)
	})
}

func Fuzz_Short7(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var x1 uintptr
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&x1)

		fuzzwrapexamples.Short7(x1)
	})
}

func Fuzz_Short8(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var x1 unsafe.Pointer
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&x1)

		fuzzwrapexamples.Short8(x1)
	})
}

func Fuzz_TypesShortListFill(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var x1 int
		var x2 *int
		var x3 **int
		var x4 map[string]string
		var x5 *map[string]string
		var x6 fuzzwrapexamples.MyInt
		var x7 [4]int
		var x8 fuzzwrapexamples.MyStruct
		var x9 io.ByteReader
		var x10 io.RuneReader
		var x11 io.ByteWriter
		var x12 io.ReadWriter
		var x13 io.ReaderFrom
		var x14 io.StringWriter
		var x15 io.Closer
		var x16 io.ReadCloser
		var x17 context.Context
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&x1, &x2, &x3, &x4, &x5, &x6, &x7, &x8, &x9, &x10, &x11, &x12, &x13, &x14, &x15, &x16, &x17)
		if x2 == nil || x3 == nil || x5 == nil {
			return
		}

		fuzzwrapexamples.TypesShortListFill(x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17)
	})
}

func Fuzz_TypesShortListNoFill(f *testing.F) {
	f.Fuzz(func(t *testing.T, x1 int, x5 string) {
		fuzzwrapexamples.TypesShortListNoFill(x1, x5)
	})
}

// skipping Fuzz_TypesShortListSkip1 because parameters include unsupported func or chan: chan bool

// skipping Fuzz_TypesShortListSkip2 because parameters include unsupported func or chan: func(int)
