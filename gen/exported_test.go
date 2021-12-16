package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// the simplest one to run is:
//   go test -run=Exported/exported_tests:_exported_only,_not_local_pkg

func TestExported(t *testing.T) {
	tests := []struct {
		name         string
		onlyExported bool
		qualifyAll   bool
		want         string
	}{
		{
			name:         "exported tests: exported only, not local pkg",
			onlyExported: true,
			qualifyAll:   true,
			want: `package fuzzwrapexamplesfuzz // rename if needed

// if needed, fill in imports or run 'goimports'
import "io"

func Fuzz_TypeExported_PointerExportedMethod(t *fuzzwrapexamples.TypeExported, i int) {
	if t == nil {
		return
	}
	t.PointerExportedMethod(i)
}

func Fuzz_TypeExported_NonPointerExportedMethod(t fuzzwrapexamples.TypeExported, i int) {
	t.NonPointerExportedMethod(i)
}

func Fuzz_FuncExported(i int) {
	fuzzwrapexamples.FuncExported(i)
}

func Fuzz_FuncExportedUsesSupportedInterface(w io.Reader) {
	fuzzwrapexamples.FuncExportedUsesSupportedInterface(w)
}

// skipping Fuzz_FuncExportedUsesUnsupportedInterface because parameters include interfaces or funcs: github.com/thepudds/fzgo/genfuzzfuncs/examples/test-exported.ExportedInterface
`},
		{
			name:         "exported tests: exported only, local pkg",
			onlyExported: true,
			qualifyAll:   false,
			want: `package fuzzwrapexamples

// if needed, fill in imports or run 'goimports'
import "io"

func Fuzz_TypeExported_PointerExportedMethod(t *TypeExported, i int) {
	if t == nil {
		return
	}
	t.PointerExportedMethod(i)
}

func Fuzz_TypeExported_NonPointerExportedMethod(t TypeExported, i int) {
	t.NonPointerExportedMethod(i)
}

func Fuzz_FuncExported(i int) {
	FuncExported(i)
}

func Fuzz_FuncExportedUsesSupportedInterface(w io.Reader) {
	FuncExportedUsesSupportedInterface(w)
}

// skipping Fuzz_FuncExportedUsesUnsupportedInterface because parameters include interfaces or funcs: github.com/thepudds/fzgo/genfuzzfuncs/examples/test-exported.ExportedInterface
`},
		{
			name:         "exported tests: exported and not exported, not local package",
			onlyExported: false,
			qualifyAll:   true,
			want: `package fuzzwrapexamplesfuzz // rename if needed

// if needed, fill in imports or run 'goimports'
import "io"

func Fuzz_TypeExported_PointerExportedMethod(t *fuzzwrapexamples.TypeExported, i int) {
	if t == nil {
		return
	}
	t.PointerExportedMethod(i)
}

func Fuzz_TypeExported_pointerRcvNotExportedMethod(t *fuzzwrapexamples.TypeExported, i int) {
	if t == nil {
		return
	}
	t.pointerRcvNotExportedMethod(i)
}

func Fuzz_typeNotExported_PointerExportedMethod(t *fuzzwrapexamples.typeNotExported, i int) {
	if t == nil {
		return
	}
	t.PointerExportedMethod(i)
}

func Fuzz_typeNotExported_pointerRcvNotExportedMethod(t *fuzzwrapexamples.typeNotExported, i int) {
	if t == nil {
		return
	}
	t.pointerRcvNotExportedMethod(i)
}

func Fuzz_TypeExported_NonPointerExportedMethod(t fuzzwrapexamples.TypeExported, i int) {
	t.NonPointerExportedMethod(i)
}

func Fuzz_TypeExported_nonPointerRcvNotExportedMethod(t fuzzwrapexamples.TypeExported, i int) {
	t.nonPointerRcvNotExportedMethod(i)
}

func Fuzz_typeNotExported_NonPointerExportedMethod(t fuzzwrapexamples.typeNotExported, i int) {
	t.NonPointerExportedMethod(i)
}

func Fuzz_typeNotExported_nonPointerRcvNotExportedMethod(t fuzzwrapexamples.typeNotExported, i int) {
	t.nonPointerRcvNotExportedMethod(i)
}

func Fuzz_FuncExported(i int) {
	fuzzwrapexamples.FuncExported(i)
}

func Fuzz_FuncExportedUsesSupportedInterface(w io.Reader) {
	fuzzwrapexamples.FuncExportedUsesSupportedInterface(w)
}

// skipping Fuzz_FuncExportedUsesUnsupportedInterface because parameters include interfaces or funcs: github.com/thepudds/fzgo/genfuzzfuncs/examples/test-exported.ExportedInterface

func Fuzz_funcNotExported(i int) {
	fuzzwrapexamples.funcNotExported(i)
}
`},
		{
			name:         "exported tests: exported and not exported, local package",
			onlyExported: false,
			qualifyAll:   false,
			want: `package fuzzwrapexamples

// if needed, fill in imports or run 'goimports'
import "io"

func Fuzz_TypeExported_PointerExportedMethod(t *TypeExported, i int) {
	if t == nil {
		return
	}
	t.PointerExportedMethod(i)
}

func Fuzz_TypeExported_pointerRcvNotExportedMethod(t *TypeExported, i int) {
	if t == nil {
		return
	}
	t.pointerRcvNotExportedMethod(i)
}

func Fuzz_typeNotExported_PointerExportedMethod(t *typeNotExported, i int) {
	if t == nil {
		return
	}
	t.PointerExportedMethod(i)
}

func Fuzz_typeNotExported_pointerRcvNotExportedMethod(t *typeNotExported, i int) {
	if t == nil {
		return
	}
	t.pointerRcvNotExportedMethod(i)
}

func Fuzz_TypeExported_NonPointerExportedMethod(t TypeExported, i int) {
	t.NonPointerExportedMethod(i)
}

func Fuzz_TypeExported_nonPointerRcvNotExportedMethod(t TypeExported, i int) {
	t.nonPointerRcvNotExportedMethod(i)
}

func Fuzz_typeNotExported_NonPointerExportedMethod(t typeNotExported, i int) {
	t.NonPointerExportedMethod(i)
}

func Fuzz_typeNotExported_nonPointerRcvNotExportedMethod(t typeNotExported, i int) {
	t.nonPointerRcvNotExportedMethod(i)
}

func Fuzz_FuncExported(i int) {
	FuncExported(i)
}

func Fuzz_FuncExportedUsesSupportedInterface(w io.Reader) {
	FuncExportedUsesSupportedInterface(w)
}

// skipping Fuzz_FuncExportedUsesUnsupportedInterface because parameters include interfaces or funcs: github.com/thepudds/fzgo/genfuzzfuncs/examples/test-exported.ExportedInterface

func Fuzz_funcNotExported(i int) {
	funcNotExported(i)
}
`},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgPattern := "github.com/thepudds/fzgo/genfuzzfuncs/examples/test-exported"
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
				insertConstructors: true,
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
