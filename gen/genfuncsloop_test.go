package gen

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/imports"
)

// to update golden files in ./testdata:
//   go test -update

// The first subtest here is the simplest & most useful single test in the file. To run just that:
//    go test -run=Race/race_exported_not_local_pkg

func TestChainRace(t *testing.T) {
	tests := []struct {
		name         string // Note: we use the test name also as the golden filename
		onlyExported bool
		qualifyAll   bool
		parallel     bool
	}{
		{
			name:         "race_exported_not_local_pkg.go",
			onlyExported: true,
			qualifyAll:   true,
			parallel:     true,
		},
		{
			name:         "race_exported_local_pkg.go",
			onlyExported: true,
			qualifyAll:   false,
			parallel:     false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pkgPattern := "github.com/thepudds/fzgen/examples/inputs/race"
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
				insertConstructors: true,
				parallel:           tt.parallel,
			}

			out, err := emitChainWrappers(pkgPattern, pkgs[0], "examplefuzz", wrapperOpts)
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
				t.Errorf("emitChainWrappers() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestChainUUID(t *testing.T) {
	tests := []struct {
		name         string // Note: we use the test name also as the golden filename
		onlyExported bool
		parallel     bool
		qualifyAll   bool
	}{
		{
			name:         "uuid_exported_local_pkg.go",
			onlyExported: true,
			parallel:     true,
			qualifyAll:   false,
		},
		{
			name:         "uuid_exported_not_local_pkg.go",
			onlyExported: true,
			parallel:     true,
			qualifyAll:   true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pkgPattern := "github.com/thepudds/fzgen/examples/inputs/test-chain-uuid"
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
				insertConstructors: true,
				parallel:           tt.parallel,
			}

			out, err := emitChainWrappers(pkgPattern, pkgs[0], "examplefuzz", wrapperOpts)
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
				t.Errorf("emitChainWrappers() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestChainNilChecks(t *testing.T) {
	tests := []struct {
		name         string // Note: we use the test name also as the golden filename
		onlyExported bool
		qualifyAll   bool
		parallel     bool
	}{
		{
			name:         "nil_checks_exported_not_local_pkg.go",
			onlyExported: true,
			qualifyAll:   true,
			parallel:     false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			pkgPattern := "github.com/thepudds/fzgen/examples/inputs/test-types"
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
				insertConstructors: true,
				parallel:           tt.parallel,
			}

			out, err := emitChainWrappers(pkgPattern, pkgs[0], "examplefuzz", wrapperOpts)
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
				t.Errorf("emitChainWrappers() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
