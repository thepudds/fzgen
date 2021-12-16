package fzgen

import (
	"flag"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// to update golden files in ./testdata:
//   go test -update
var updateFlag = flag.Bool("update", false, "update golden files")

// The first subtest here is the simplest & fatest test in the file. To run just that:
//    go test -run=Tyes/types_exported_not_local_pkg

func TestTypes(t *testing.T) {
	tests := []struct {
		name         string // Note: we use the test name also as the golden filename
		onlyExported bool
		qualifyAll   bool
	}{
		{
			name:         "types_exported_not_local_pkg.go",
			onlyExported: true,
			qualifyAll:   true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pkgPattern := "github.com/thepudds/fzgen/examples/inputs/test-types"
			options := flagExcludeFuzzPrefix | flagAllowMultiFuzz
			if tt.onlyExported {
				options |= flagRequireExported
			}
			functions, err := findFunc(pkgPattern, ".", nil, options)
			if err != nil {
				t.Fatalf("FindFuncfail() failed: %v", err)
			}

			wrapperOpts := wrapperOptions{
				qualifyAll:         tt.qualifyAll,
				insertConstructors: true,
				constructorPattern: "^New",
			}

			out, err := emitIndependentWrappers(pkgPattern, functions, wrapperOpts)
			if err != nil {
				t.Fatalf("createWrappers() failed: %v", err)
			}

			got := string(out)
			golden := filepath.Join("..", "testdata", tt.name)
			if *updateFlag {
				// Note: using Fatalf above including so that we don't update if there was an earlier failure.
				err = ioutil.WriteFile(golden, []byte(got), 0o644)
				if err != nil {
					t.Fatalf("failed to update golden file: %v", err)
				}
			}
			b, err := ioutil.ReadFile(golden)
			if err != nil {
				t.Fatalf("failed to read golden file: %v", err)
			}
			want := string(b)
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("createWrappers() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// the simplest to run is:
//    go test -run=ConstructorInjection/constructor_injection:_exported,_not_local_pkg

func TestConstructorInjection(t *testing.T) {
	tests := []struct {
		name               string // Note: we use the test name also as the golden filename
		onlyExported       bool
		qualifyAll         bool
		injectConstructors bool
	}{
		{
			// this corresponds roughly to:
			//    fzgen -ctors -pkg=github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection
			name:               "inject_ctor_true_exported_not_local_pkg.go",
			onlyExported:       true,
			qualifyAll:         true,
			injectConstructors: true,
		},
		{
			// this corresponds roughly to:
			//    fzgen -ctors=false -pkg=github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection
			name:               "inject_ctor_false_exported_not_local_pkg.go",
			onlyExported:       true,
			qualifyAll:         true,
			injectConstructors: false,
		},
		{
			// this corresponds roughly to:
			//    genfuzzfuncs -ctors -qualifyall=false -pkg=github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection
			name:               "inject_ctor_true_exported_local_pkg.go",
			onlyExported:       true,
			qualifyAll:         false,
			injectConstructors: true,
		},
		{
			// this corresponds roughly to:
			//    genfuzzfuncs -ctors=false -qualifyall=false -pkg=github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection
			name:               "inject_ctor_false_exported_local_pkg.go",
			onlyExported:       true,
			qualifyAll:         false,
			injectConstructors: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgPattern := "github.com/thepudds/fzgen/examples/inputs/test-constructor-injection"
			options := flagExcludeFuzzPrefix | flagAllowMultiFuzz
			if tt.onlyExported {
				options |= flagRequireExported
			}
			functions, err := findFunc(pkgPattern, ".", nil, options)
			if err != nil {
				t.Fatalf("FindFuncfail() failed: %v", err)
			}

			wrapperOpts := wrapperOptions{
				qualifyAll:         tt.qualifyAll,
				insertConstructors: tt.injectConstructors,
				constructorPattern: "^New",
			}
			out, err := emitIndependentWrappers(pkgPattern, functions, wrapperOpts)
			if err != nil {
				t.Fatalf("createWrappers() failed: %v", err)
			}

			got := string(out)
			golden := filepath.Join("..", "testdata", tt.name)
			if *updateFlag {
				// Note: using Fatalf above including so that we don't update if there was an earlier failure.
				err = ioutil.WriteFile(golden, []byte(got), 0o644)
				if err != nil {
					t.Fatalf("failed to update golden file: %v", err)
				}
			}
			b, err := ioutil.ReadFile(golden)
			if err != nil {
				t.Fatalf("failed to read golden file: %v", err)
			}
			want := string(b)
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("createWrappers() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// the simplest one to run is:
//   go test -run=TestExported/exported_not_local_pkg
// to update golden files in ./testdata:
//   go test -update -run=TestExported/exported_not_local_pkg
// or to update all the TestExported golden files:
//   go test -update -run=TestExported

func TestExported(t *testing.T) {
	tests := []struct {
		name         string // Note: we use the test name also as the golden filename
		onlyExported bool
		qualifyAll   bool
	}{
		{
			name:         "exported_not_local_pkg.go",
			onlyExported: true,
			qualifyAll:   true,
		},
		{
			name:         "exported_local_pkg.go",
			onlyExported: true,
			qualifyAll:   false,
		},
		{
			name:         "exported_and_private_not_local_pkg.go",
			onlyExported: false,
			qualifyAll:   true,
		},
		{
			name:         "exported_and_private_local_pkg.go",
			onlyExported: false,
			qualifyAll:   false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pkgPattern := "github.com/thepudds/fzgen/examples/inputs/test-exported"
			options := flagExcludeFuzzPrefix | flagAllowMultiFuzz
			if tt.onlyExported {
				options |= flagRequireExported
			}
			functions, err := findFunc(pkgPattern, ".", nil, options)
			if err != nil {
				t.Fatalf("FindFuncfail() failed: %v", err)
			}

			wrapperOpts := wrapperOptions{
				qualifyAll:         tt.qualifyAll,
				insertConstructors: true,
				constructorPattern: "^New",
			}

			out, err := emitIndependentWrappers(pkgPattern, functions, wrapperOpts)
			if err != nil {
				t.Fatalf("createWrappers() failed: %v", err)
			}

			got := string(out)
			golden := filepath.Join("..", "testdata", tt.name)
			if *updateFlag {
				// Note: using Fatalf above including so that we don't update if there was an earlier failure.
				err = ioutil.WriteFile(golden, []byte(got), 0o644)
				if err != nil {
					t.Fatalf("failed to update golden file: %v", err)
				}
			}
			b, err := ioutil.ReadFile(golden)
			if err != nil {
				t.Fatalf("failed to read golden file: %v", err)
			}
			want := string(b)
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("createWrappers() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
