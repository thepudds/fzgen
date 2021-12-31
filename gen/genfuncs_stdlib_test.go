package gen

import (
	"io/ioutil"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/imports"
)

func TestStrings(t *testing.T) {
	if testing.Short() {
		// TODO: probably remove this test at some point?
		t.Skip("skipping stdlib test in short mode")
	}
	if !strings.HasPrefix(runtime.Version(), "go1.17") {
		t.Skip("skipping stdlib test because it expects strings package from Go 1.17")
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
			options := flagExcludeFuzzPrefix | flagMultiMatch
			if tt.onlyExported {
				options |= flagRequireExported
			}
			pkgs, err := findFuncsGrouped(pkgPattern, ".", "^New", options)
			if err != nil {
				t.Fatalf("findFuncsGrouped() failed: %v", err)
			}
			if len(pkgs) != 1 {
				t.Fatalf("findFuncsGrouped() found unexpected pkgs count: %d", len(pkgs))
			}

			wrapperOpts := wrapperOptions{
				qualifyAll:         tt.qualifyAll,
				insertConstructors: tt.insertConstructors,
			}
			out, err := emitIndependentWrappers(pkgPattern, pkgs[0], "examplefuzz", wrapperOpts)
			if err != nil {
				t.Fatalf("createWrappers() failed: %v", err)
			}
			out, err = imports.Process("autofuzz_test.go", out, nil)
			if err != nil {
				t.Fatalf("imports.Process() failed: %v", err)
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
