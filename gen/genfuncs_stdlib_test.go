//go:build go1.17
// +build go1.17

package fzgen

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestStrings(t *testing.T) {
	if testing.Short() {
		// TODO: probably remove this test at some point?
		// It is long, and sensitive to changes in stdlib strings pkg.
		t.Skip("skipping test in short mode. also, currently relies on strings package from Go 1.17")
	}
	tests := []struct {
		name               string // Note: we use the test name also as the golden filename
		onlyExported       bool
		qualifyAll         bool
		insertConstructors bool
	}{
		{
			name:               "strings_inject_ctor_true_exported_not_local_pkg.go",
			onlyExported:       true,
			qualifyAll:         true,
			insertConstructors: true,
		},
		{
			name:               "strings_inject_ctor_false_exported_local_pkg.go",
			onlyExported:       true,
			qualifyAll:         false,
			insertConstructors: true,
		},
		{
			name:               "strings_inject_ctor_false_exported_not_local_pkg.go",
			onlyExported:       true,
			qualifyAll:         true,
			insertConstructors: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pkgPattern := "strings"
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
				insertConstructors: tt.insertConstructors,
				constructorPattern: "^New",
			}
			out, err := emitIndependentWrappers(pkgPattern, functions, wrapperOpts)
			if err != nil {
				t.Fatalf("createWrappers() failed: %v", err)
			}

			got := string(out)
			golden := filepath.Join("..", "testdata", tt.name)
			if *updateFlag {
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
