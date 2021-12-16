package fzgen

import (
	"fmt"
	"go/types"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/thepudds/fzgen/gen/internal/mod"
	"golang.org/x/tools/go/packages"
)

// FindFuncFlag describes bitwise flags for FindFunc
// TODO: this is a temporary fork from fzgo/fuzz.FindFunc.
type FindFuncFlag uint

const (
	flagAllowMultiFuzz FindFuncFlag = 1 << iota
	flagRequireFuzzPrefix
	flagExcludeFuzzPrefix
	flagRequireExported
)

// findFunc searches for requested functions matching a package pattern and func pattern.
// TODO: this is a temporary fork from fzgo/fuzz.findFunc.
// TODO: maybe change flags to a predicate function?
func findFunc(pkgPattern, funcPattern string, env []string, flags FindFuncFlag) ([]mod.Func, error) {
	report := func(err error) error {
		return fmt.Errorf("error while loading packages for pattern %v: %v", pkgPattern, err)
	}
	var result []mod.Func

	// load packages based on our package pattern
	// TODO: set build tags? Previously: BuildFlags: []string{buildTagsArg}, retain? probably not needed.
	// build tags example: https://groups.google.com/d/msg/golang-tools/Adwr7jEyDmw/wQZ5qi8ZGAAJ
	cfg := &packages.Config{
		Mode: packages.LoadSyntax,
		// TODO: packages.LoadSyntax is deprecated, so consider something similar to:
		//    Mode: packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
		// However, that specific change is not correct.
		// With that change, 'fzgen -pkg=github.com/google/uuid' from an empty directory in
		// a module with correct uuid 'require' fails with error:
		//    error while loading packages for pattern github.com/google/uuid: failed to find directory for package "": exit status 1
		// Note empty string for what should be the package path at "...directory for package %q"?
		// Maybe revist only after restoring end-to-end testing via testscripts.
	}
	if len(env) > 0 {
		cfg.Env = env
	}
	pkgs, err := packages.Load(cfg, pkgPattern)
	if err != nil {
		return nil, report(err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		return nil, fmt.Errorf("package load error for package pattern %v", pkgPattern)
	}

	// look for a func that starts with 'Fuzz' and matches our regexp.
	// loop over the packages we found and loop over the Defs for each package.
	for _, pkg := range pkgs {
		// TODO: consider alternative: "from a Package, look at Syntax.Scope.Objects and filter with ast.IsExported."
		for id, obj := range pkg.TypesInfo.Defs {
			// check if we have a func
			f, ok := obj.(*types.Func)
			if ok {
				if isInterfaceRecv(f) {
					// TODO: control via flag?
					// TODO: merge back to fzgo/fuzz.FindFunc?
					continue
				}
				if flags&flagExcludeFuzzPrefix != 0 && strings.HasPrefix(id.Name, "Fuzz") {
					// skip any function that already starts with Fuzz
					continue
				}
				if flags&flagRequireFuzzPrefix != 0 && !strings.HasPrefix(id.Name, "Fuzz") {
					// skip any function that does not start with Fuzz
					continue
				}
				if flags&flagRequireExported != 0 {
					if !isExportedFunc(f) {
						continue
					}
				}

				matchedPattern, err := regexp.MatchString(funcPattern, id.Name)
				if err != nil {
					return nil, report(err)
				}
				if matchedPattern {
					// found a match.
					// check if we already found a match in a prior iteration our of chains.
					if len(result) > 0 && flags&flagAllowMultiFuzz == 0 {
						return nil, fmt.Errorf("multiple matches not allowed. multiple matches for pattern %v and func %v: %v.%v and %v.%v",
							pkgPattern, funcPattern, pkg.PkgPath, id.Name, result[0].PkgPath, result[0].FuncName)
					}
					pkgDir, err := goListDir(pkg.PkgPath, env)
					if err != nil {
						return nil, report(err)
					}

					function := mod.Func{
						FuncName: id.Name, PkgName: pkg.Name, PkgPath: pkg.PkgPath, PkgDir: pkgDir,
						TypesFunc: f,
					}
					result = append(result, function)

					// keep chaining to see if we find another match
				}
			}
		}
	}
	// done looking
	if len(result) == 0 {
		return nil, fmt.Errorf("failed to find any functions for package pattern %q and func pattern %q", pkgPattern, funcPattern)
	}
	return result, nil
}

// goListDir returns the dir for a package import path.
func goListDir(pkgPath string, env []string) (string, error) {
	if len(env) == 0 {
		env = os.Environ()
	}

	// TODO: use build tags, or not?
	// cmd := exec.Command("go", "list", "-f", "{{.Dir}}", buildTagsArg, pkgPath)
	cmd := exec.Command("go", "list", "-f", "{{.Dir}}", pkgPath)
	cmd.Env = env
	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		// If this fails with a pkgPath as empty string, check packages.Config.Mode
		fmt.Fprintf(os.Stderr, "fzgen: 'go list -f {{.Dir}} %v' failed for pkgPath %q\n%v\n", pkgPath, pkgPath, string(out))
		return "", fmt.Errorf("failed to find directory for package %q: %v", pkgPath, err)
	}
	result := strings.TrimSpace(string(out))
	if strings.Contains(result, "\n") {
		return "", fmt.Errorf("multiple directory results for package %v", pkgPath)
	}
	return result, nil
}

// TODO: would be good to find some canonical documentation or example of this.
func isExportedFunc(f *types.Func) bool {
	if !f.Exported() {
		return false
	}
	// the function itself is exported, but it might be a method on an unexported type.
	sig, ok := f.Type().(*types.Signature)
	if !ok {
		return false
	}
	recv := sig.Recv()
	if recv == nil {
		// not a method, and the func itself is exported.
		return true
	}

	n, err := findReceiverNamedType(recv)
	if err != nil {
		// don't treat as fatal error.
		fmt.Fprintf(os.Stderr, "genfuzzfuncs: warning: failed to determine if exported for receiver %v for func %v: %v\n",
			recv, f, err)
		return false
	}

	return n.Obj().Exported()
}

// isInterfaceRecv helps filter out interface receivers such as 'func (interface).Is(error) bool'
// Previously would have issues from errors.Is:
//    x, ok := err.(interface{ Is(error) bool }); ok && x.Is(target)
func isInterfaceRecv(f *types.Func) bool {
	sig, ok := f.Type().(*types.Signature)
	if !ok {
		return false
	}
	recv := sig.Recv()
	if recv == nil {
		// not a method
		return false
	}
	// TODO: should this be Type().Underlying()?
	_, ok = recv.Type().(*types.Interface)
	return ok
}
