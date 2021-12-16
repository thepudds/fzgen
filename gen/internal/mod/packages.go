package fuzz

import (
	"fmt"
	"go/types"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

const buildTagsArg = "-tags=gofuzz fuzz"

// Func represents a discovered function that will be fuzzed.
type Func struct {
	FuncName  string
	PkgName   string      // package name (should be the same as the package's package statement)
	PkgPath   string      // import path
	PkgDir    string      // local on-disk directory
	TypesFunc *types.Func // auxiliary information about a Func from the go/types package
}

// FuzzName returns the '<pkg>.<OrigFuzzFunc>' string.
// For example, it might be 'fmt.FuzzFmt'. This is used
// in messages, as well it is part of the path when creating
// the corpus location under testdata.
func (f *Func) FuzzName() string {
	return fmt.Sprintf("%s.%s", f.PkgName, f.FuncName)
}

func (f *Func) String() string {
	return f.FuzzName()
}

// FindFunc searches for a requested function to fuzz.
// It is not an error to not find any -- in that case, it returns a nil list and nil error.
// The March 2017 proposal document https://github.com/golang/go/issues/19109#issuecomment-285456008
// suggests not allowing something like 'go test -fuzz=. ./...' to match multiple fuzz functions.
// As an experiment, allowMultiFuzz flag allows that.
// FindFunc also allows for multiple packages in pkgPattern separated by whitespace.
func FindFunc(pkgPattern, funcPattern string, env []string, allowMultiFuzz bool) ([]Func, error) {
	report := func(err error) error {
		return fmt.Errorf("error while loading packages for pattern %v: %v", pkgPattern, err)
	}
	var result []Func

	// load packages based on our package pattern
	// build tags example: https://groups.google.com/d/msg/golang-tools/Adwr7jEyDmw/wQZ5qi8ZGAAJ
	cfg := &packages.Config{
		Mode:       packages.LoadSyntax,
		BuildFlags: []string{buildTagsArg},
	}
	if len(env) > 0 {
		cfg.Env = env
	}
	pkgs, err := packages.Load(cfg, strings.Fields(pkgPattern)...)
	if err != nil {
		return nil, report(err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		return nil, fmt.Errorf("package load error for package pattern %v", pkgPattern)
	}

	// look for a func that starts with 'Fuzz' and matches our regexp.
	// loop over the packages we found and loop over the Defs for each package.
	for _, pkg := range pkgs {
		for id, obj := range pkg.TypesInfo.Defs {
			// check if we have a func
			f, ok := obj.(*types.Func)
			if ok {

				// check if it starts with "Fuzz" and matches our fuzz function regular expression
				if !strings.HasPrefix(id.Name, "Fuzz") {
					continue
				}

				matchedPattern, err := regexp.MatchString(funcPattern, id.Name)
				if err != nil {
					return nil, report(err)
				}
				if matchedPattern {
					// found a match.
					// check if we already found a match in a prior iteration our of loops.
					if len(result) > 0 && !allowMultiFuzz {
						return nil, fmt.Errorf("multiple matches not allowed. multiple matches for pattern %v and func %v: %v.%v and %v.%v",
							pkgPattern, funcPattern, pkg.PkgPath, id.Name, result[0].PkgPath, result[0].FuncName)
					}
					pkgDir, err := goListDir(pkg.PkgPath, env)
					if err != nil {
						return nil, report(err)
					}

					function := Func{
						FuncName: id.Name, PkgName: pkg.Name, PkgPath: pkg.PkgPath, PkgDir: pkgDir,
						TypesFunc: f,
					}
					result = append(result, function)

					// keep looping to see if we find another match
				}
			}
		}
	}
	// done looking
	if len(result) == 0 {
		return nil, fmt.Errorf("failed to find fuzz function for pattern %v and func %v", pkgPattern, funcPattern)
	}
	// put our found functions into a deterministic order
	sort.Slice(result, func(i, j int) bool {
		// types.Func.String outputs strings like:
		//   func (github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection.A).ValMethodWithArg(i int) bool
		// works ok for clustering results, though pointer receiver and non-pointer receiver methods don't cluster.
		// for direct fuzzing, we only support functions, not methods, though for wrapping (outside of fzgo itself) we support methods.
		// could strip '*' or sort another way, but probably ok, at least for now.
		return result[i].TypesFunc.String() < result[j].TypesFunc.String()
	})

	return result, nil
}

// goListDir returns the dir for a package import path
func goListDir(pkgPath string, env []string) (string, error) {
	if len(env) == 0 {
		env = os.Environ()
	}

	cmd := exec.Command("go", "list", "-f", "{{.Dir}}", buildTagsArg, pkgPath)
	cmd.Env = env

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to find directory of %v: %v", pkgPath, err)
	}
	result := strings.TrimSpace(string(out))
	if strings.Contains(result, "\n") {
		return "", fmt.Errorf("multiple directory results for package %v", pkgPath)
	}
	return result, nil
}
