package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// the simplest to run is:
//    go test -run=ConstructorInjection/constructor_injection:_exported_only,_not_local_pkg

func TestConstructorInjection(t *testing.T) {
	tests := []struct {
		name               string
		onlyExported       bool
		qualifyAll         bool
		injectConstructors bool
		want               string
	}{
		{
			// this corresponds roughly to:
			//    genfuzzfuncs -ctors -pkg=github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection
			name:               "constructor injection: exported only, not local pkg",
			onlyExported:       true,
			qualifyAll:         true,
			injectConstructors: true,
			want: `package fuzzwrapexamplesfuzz // rename if needed

// if needed, fill in imports or run 'goimports'
import "bufio"

func Fuzz_A_PtrMethodNoArg(c int) {
	r := fuzzwrapexamples.NewAPtr(c)
	r.PtrMethodNoArg()
}

func Fuzz_A_PtrMethodWithArg(c int, i int) {
	r := fuzzwrapexamples.NewAPtr(c)
	r.PtrMethodWithArg(i)
}

func Fuzz_B_PtrMethodNoArg(c int) {
	r := fuzzwrapexamples.NewBVal(c)
	r.PtrMethodNoArg()
}

func Fuzz_B_PtrMethodWithArg(c int, i int) {
	r := fuzzwrapexamples.NewBVal(c)
	r.PtrMethodWithArg(i)
}

func Fuzz_Package_SetName(path string, n2 string, n3 string) {
	pkg := fuzzwrapexamples.NewPackage(path, n2)
	pkg.SetName(n3)
}

func Fuzz_Z_ReadLine(z *bufio.Reader) {
	if z == nil {
		return
	}
	z1 := fuzzwrapexamples.NewZ(z)
	z1.ReadLine()
}

func Fuzz_A_ValMethodNoArg(c int) {
	r := fuzzwrapexamples.NewAPtr(c)
	r.ValMethodNoArg()
}

func Fuzz_A_ValMethodWithArg(c int, i int) {
	r := fuzzwrapexamples.NewAPtr(c)
	r.ValMethodWithArg(i)
}

func Fuzz_B_ValMethodNoArg(c int) {
	r := fuzzwrapexamples.NewBVal(c)
	r.ValMethodNoArg()
}

func Fuzz_B_ValMethodWithArg(c int, i int) {
	r := fuzzwrapexamples.NewBVal(c)
	r.ValMethodWithArg(i)
}

func Fuzz_NewAPtr(c int) {
	fuzzwrapexamples.NewAPtr(c)
}

func Fuzz_NewBVal(c int) {
	fuzzwrapexamples.NewBVal(c)
}

func Fuzz_NewPackage(path string, name string) {
	fuzzwrapexamples.NewPackage(path, name)
}

func Fuzz_NewZ(z *bufio.Reader) {
	if z == nil {
		return
	}
	fuzzwrapexamples.NewZ(z)
}
`},
		{
			// this corresponds roughly to:
			//    genfuzzfuncs -ctors=false -pkg=github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection
			name:               "no constructor injection: exported only, not local pkg",
			onlyExported:       true,
			qualifyAll:         true,
			injectConstructors: false,
			want: `package fuzzwrapexamplesfuzz // rename if needed

// if needed, fill in imports or run 'goimports'
import "bufio"

func Fuzz_A_PtrMethodNoArg(r *fuzzwrapexamples.A) {
	if r == nil {
		return
	}
	r.PtrMethodNoArg()
}

func Fuzz_A_PtrMethodWithArg(r *fuzzwrapexamples.A, i int) {
	if r == nil {
		return
	}
	r.PtrMethodWithArg(i)
}

func Fuzz_B_PtrMethodNoArg(r *fuzzwrapexamples.B) {
	if r == nil {
		return
	}
	r.PtrMethodNoArg()
}

func Fuzz_B_PtrMethodWithArg(r *fuzzwrapexamples.B, i int) {
	if r == nil {
		return
	}
	r.PtrMethodWithArg(i)
}

func Fuzz_Package_SetName(pkg *fuzzwrapexamples.Package, name string) {
	if pkg == nil {
		return
	}
	pkg.SetName(name)
}

func Fuzz_Z_ReadLine(z *fuzzwrapexamples.Z) {
	if z == nil {
		return
	}
	z.ReadLine()
}

func Fuzz_A_ValMethodNoArg(r fuzzwrapexamples.A) {
	r.ValMethodNoArg()
}

func Fuzz_A_ValMethodWithArg(r fuzzwrapexamples.A, i int) {
	r.ValMethodWithArg(i)
}

func Fuzz_B_ValMethodNoArg(r fuzzwrapexamples.B) {
	r.ValMethodNoArg()
}

func Fuzz_B_ValMethodWithArg(r fuzzwrapexamples.B, i int) {
	r.ValMethodWithArg(i)
}

func Fuzz_NewAPtr(c int) {
	fuzzwrapexamples.NewAPtr(c)
}

func Fuzz_NewBVal(c int) {
	fuzzwrapexamples.NewBVal(c)
}

func Fuzz_NewPackage(path string, name string) {
	fuzzwrapexamples.NewPackage(path, name)
}

func Fuzz_NewZ(z *bufio.Reader) {
	if z == nil {
		return
	}
	fuzzwrapexamples.NewZ(z)
}
`},
		{
			// this corresponds roughly to:
			//    genfuzzfuncs -ctors -qualifyall=false -pkg=github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection
			name:               "constructor injection: exported only, local pkg",
			onlyExported:       true,
			qualifyAll:         false,
			injectConstructors: true,
			want: `package fuzzwrapexamples

// if needed, fill in imports or run 'goimports'
import "bufio"

func Fuzz_A_PtrMethodNoArg(c int) {
	r := NewAPtr(c)
	r.PtrMethodNoArg()
}

func Fuzz_A_PtrMethodWithArg(c int, i int) {
	r := NewAPtr(c)
	r.PtrMethodWithArg(i)
}

func Fuzz_B_PtrMethodNoArg(c int) {
	r := NewBVal(c)
	r.PtrMethodNoArg()
}

func Fuzz_B_PtrMethodWithArg(c int, i int) {
	r := NewBVal(c)
	r.PtrMethodWithArg(i)
}

func Fuzz_Package_SetName(path string, n2 string, n3 string) {
	pkg := NewPackage(path, n2)
	pkg.SetName(n3)
}

func Fuzz_Z_ReadLine(z *bufio.Reader) {
	if z == nil {
		return
	}
	z1 := NewZ(z)
	z1.ReadLine()
}

func Fuzz_A_ValMethodNoArg(c int) {
	r := NewAPtr(c)
	r.ValMethodNoArg()
}

func Fuzz_A_ValMethodWithArg(c int, i int) {
	r := NewAPtr(c)
	r.ValMethodWithArg(i)
}

func Fuzz_B_ValMethodNoArg(c int) {
	r := NewBVal(c)
	r.ValMethodNoArg()
}

func Fuzz_B_ValMethodWithArg(c int, i int) {
	r := NewBVal(c)
	r.ValMethodWithArg(i)
}

func Fuzz_NewAPtr(c int) {
	NewAPtr(c)
}

func Fuzz_NewBVal(c int) {
	NewBVal(c)
}

func Fuzz_NewPackage(path string, name string) {
	NewPackage(path, name)
}

func Fuzz_NewZ(z *bufio.Reader) {
	if z == nil {
		return
	}
	NewZ(z)
}
`},
		{
			// this corresponds roughly to:
			//    genfuzzfuncs -ctors=false -qualifyall=false -pkg=github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection
			name:               "no constructor injection: exported only, local pkg",
			onlyExported:       true,
			qualifyAll:         false,
			injectConstructors: false,
			want: `package fuzzwrapexamples

// if needed, fill in imports or run 'goimports'
import "bufio"

func Fuzz_A_PtrMethodNoArg(r *A) {
	if r == nil {
		return
	}
	r.PtrMethodNoArg()
}

func Fuzz_A_PtrMethodWithArg(r *A, i int) {
	if r == nil {
		return
	}
	r.PtrMethodWithArg(i)
}

func Fuzz_B_PtrMethodNoArg(r *B) {
	if r == nil {
		return
	}
	r.PtrMethodNoArg()
}

func Fuzz_B_PtrMethodWithArg(r *B, i int) {
	if r == nil {
		return
	}
	r.PtrMethodWithArg(i)
}

func Fuzz_Package_SetName(pkg *Package, name string) {
	if pkg == nil {
		return
	}
	pkg.SetName(name)
}

func Fuzz_Z_ReadLine(z *Z) {
	if z == nil {
		return
	}
	z.ReadLine()
}

func Fuzz_A_ValMethodNoArg(r A) {
	r.ValMethodNoArg()
}

func Fuzz_A_ValMethodWithArg(r A, i int) {
	r.ValMethodWithArg(i)
}

func Fuzz_B_ValMethodNoArg(r B) {
	r.ValMethodNoArg()
}

func Fuzz_B_ValMethodWithArg(r B, i int) {
	r.ValMethodWithArg(i)
}

func Fuzz_NewAPtr(c int) {
	NewAPtr(c)
}

func Fuzz_NewBVal(c int) {
	NewBVal(c)
}

func Fuzz_NewPackage(path string, name string) {
	NewPackage(path, name)
}

func Fuzz_NewZ(z *bufio.Reader) {
	if z == nil {
		return
	}
	NewZ(z)
}
`},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgPattern := "github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection"
			options := flagExcludeFuzzPrefix | flagAllowMultiFuzz
			if tt.onlyExported {
				options |= flagRequireExported
			}
			functions, err := FindFunc(pkgPattern, ".", nil, options)
			if err != nil {
				t.Errorf("FindFuncfail() failed: %v", err)
			}

			wrapperOpts := wrapperOptions{
				qualifyAll:         tt.qualifyAll,
				insertConstructors: tt.injectConstructors,
				constructorPattern: "^New",
			}
			out, err := createWrappers(pkgPattern, functions, wrapperOpts)
			if err != nil {
				t.Errorf("createWrappers() failed: %v", err)
			}

			got := string(out)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("createWrappers() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
