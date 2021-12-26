package examplefuzz

// if needed, fill in imports or run 'goimports'
import (
	"bufio"
	"testing"

	"github.com/thepudds/fzgen/fuzzer"
)

func Fuzz_A_PtrMethodNoArg(f *testing.F) {
	f.Fuzz(func(t *testing.T, c int) {
		r := NewAPtr(c)
		r.PtrMethodNoArg()
	})
}

func Fuzz_A_PtrMethodWithArg(f *testing.F) {
	f.Fuzz(func(t *testing.T, c int, i int) {
		r := NewAPtr(c)
		r.PtrMethodWithArg(i)
	})
}

func Fuzz_B_PtrMethodNoArg(f *testing.F) {
	f.Fuzz(func(t *testing.T, c int) {
		r := NewBVal(c)
		r.PtrMethodNoArg()
	})
}

func Fuzz_B_PtrMethodWithArg(f *testing.F) {
	f.Fuzz(func(t *testing.T, c int, i int) {
		r := NewBVal(c)
		r.PtrMethodWithArg(i)
	})
}

func Fuzz_MyNullUUID_UnmarshalBinary(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var nu *MyNullUUID
		var d2 []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&nu, &d2)
		if nu == nil {
			return
		}

		nu.UnmarshalBinary(d2)
	})
}

func Fuzz_MyRegexp_Expand(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var a int
		var dst []byte
		var template []byte
		var src []byte
		var match []int
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&a, &dst, &template, &src, &match)

		re, err := NewMyRegexp(a)
		if err != nil {
			return
		}
		re.Expand(dst, template, src, match)
	})
}

func Fuzz_Package_SetName(f *testing.F) {
	f.Fuzz(func(t *testing.T, path string, n2 string, n3 string) {
		pkg := NewPackage(path, n2)
		pkg.SetName(n3)
	})
}

func Fuzz_Z_ReadLine(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var z *bufio.Reader
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&z)
		if z == nil {
			return
		}

		z1 := NewZ(z)
		z1.ReadLine()
	})
}

func Fuzz_A_ValMethodNoArg(f *testing.F) {
	f.Fuzz(func(t *testing.T, c int) {
		r := NewAPtr(c)
		r.ValMethodNoArg()
	})
}

func Fuzz_A_ValMethodWithArg(f *testing.F) {
	f.Fuzz(func(t *testing.T, c int, i int) {
		r := NewAPtr(c)
		r.ValMethodWithArg(i)
	})
}

func Fuzz_B_ValMethodNoArg(f *testing.F) {
	f.Fuzz(func(t *testing.T, c int) {
		r := NewBVal(c)
		r.ValMethodNoArg()
	})
}

func Fuzz_B_ValMethodWithArg(f *testing.F) {
	f.Fuzz(func(t *testing.T, c int, i int) {
		r := NewBVal(c)
		r.ValMethodWithArg(i)
	})
}

func Fuzz_NewAPtr(f *testing.F) {
	f.Fuzz(func(t *testing.T, c int) {
		NewAPtr(c)
	})
}

func Fuzz_NewBVal(f *testing.F) {
	f.Fuzz(func(t *testing.T, c int) {
		NewBVal(c)
	})
}

func Fuzz_NewMyRegexp(f *testing.F) {
	f.Fuzz(func(t *testing.T, a int) {
		NewMyRegexp(a)
	})
}

func Fuzz_NewPackage(f *testing.F) {
	f.Fuzz(func(t *testing.T, path string, name string) {
		NewPackage(path, name)
	})
}

func Fuzz_NewZ(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var z *bufio.Reader
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&z)
		if z == nil {
			return
		}

		NewZ(z)
	})
}
