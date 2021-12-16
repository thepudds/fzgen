package fuzzwrapexamplesfuzz // rename if needed

// if needed, fill in imports or run 'goimports'
import (
	"bufio"
	"testing"

	fuzzwrapexamples "github.com/thepudds/fzgen/examples/inputs/test-constructor-injection"
	"github.com/thepudds/fzgen/fuzzer"
)

func Fuzz_A_PtrMethodNoArg(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var r *fuzzwrapexamples.A
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&r)
		if r == nil {
			return
		}

		r.PtrMethodNoArg()
	})
}

func Fuzz_A_PtrMethodWithArg(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var r *fuzzwrapexamples.A
		var i int
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&r, &i)
		if r == nil {
			return
		}

		r.PtrMethodWithArg(i)
	})
}

func Fuzz_B_PtrMethodNoArg(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var r *fuzzwrapexamples.B
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&r)
		if r == nil {
			return
		}

		r.PtrMethodNoArg()
	})
}

func Fuzz_B_PtrMethodWithArg(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var r *fuzzwrapexamples.B
		var i int
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&r, &i)
		if r == nil {
			return
		}

		r.PtrMethodWithArg(i)
	})
}

func Fuzz_MyNullUUID_UnmarshalBinary(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var nu *fuzzwrapexamples.MyNullUUID
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
		var re *fuzzwrapexamples.MyRegexp
		var dst []byte
		var template []byte
		var src []byte
		var match []int
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&re, &dst, &template, &src, &match)
		if re == nil {
			return
		}

		re.Expand(dst, template, src, match)
	})
}

func Fuzz_Package_SetName(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var pkg *fuzzwrapexamples.Package
		var name string
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&pkg, &name)
		if pkg == nil {
			return
		}

		pkg.SetName(name)
	})
}

func Fuzz_Z_ReadLine(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var z *fuzzwrapexamples.Z
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&z)
		if z == nil {
			return
		}

		z.ReadLine()
	})
}

func Fuzz_A_ValMethodNoArg(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var r fuzzwrapexamples.A
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&r)

		r.ValMethodNoArg()
	})
}

func Fuzz_A_ValMethodWithArg(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var r fuzzwrapexamples.A
		var i int
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&r, &i)

		r.ValMethodWithArg(i)
	})
}

func Fuzz_B_ValMethodNoArg(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var r fuzzwrapexamples.B
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&r)

		r.ValMethodNoArg()
	})
}

func Fuzz_B_ValMethodWithArg(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var r fuzzwrapexamples.B
		var i int
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&r, &i)

		r.ValMethodWithArg(i)
	})
}

func Fuzz_NewAPtr(f *testing.F) {
	f.Fuzz(func(t *testing.T, c int) {
		fuzzwrapexamples.NewAPtr(c)
	})
}

func Fuzz_NewBVal(f *testing.F) {
	f.Fuzz(func(t *testing.T, c int) {
		fuzzwrapexamples.NewBVal(c)
	})
}

func Fuzz_NewMyRegexp(f *testing.F) {
	f.Fuzz(func(t *testing.T, a int) {
		fuzzwrapexamples.NewMyRegexp(a)
	})
}

func Fuzz_NewPackage(f *testing.F) {
	f.Fuzz(func(t *testing.T, path string, name string) {
		fuzzwrapexamples.NewPackage(path, name)
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

		fuzzwrapexamples.NewZ(z)
	})
}
