package gen

import (
	"fmt"
	"go/types"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	"github.com/thepudds/fzgen/gen/internal/mod"
	"golang.org/x/tools/go/packages"
)

// findFuncFlag describes bitwise flags for findFunc.
// TODO: this is a temporary fork from fzgo/fuzz.FindFunc.
type findFuncFlag uint

const (
	flagMultiMatch findFuncFlag = 1 << iota
	flagRequireFuzzPrefix
	flagExcludeFuzzPrefix
	flagRequireExported
)

// Group our functions by package.
// TODO: probably rename internal/mod to internal/pkg and move these items there.
type pkg struct {
	pkgPath      string
	functions    []mod.Func
	constructors []mod.Func
}

// findFuncsGrouped searches for requested functions matching a package pattern and func pattern,
// returning them grouped by package.
func findFuncsGrouped(pkgPattern, funcPattern, constructorPattern string, flags findFuncFlag) ([]*pkg, error) {
	report := func(err error) ([]*pkg, error) {
		return nil, fmt.Errorf("finding funcs: %v", err)
	}

	funcRe, err := regexp.Compile(funcPattern)
	if err != nil {
		return report(err)
	}
	constructorRe, err := regexp.Compile(constructorPattern)
	if err != nil {
		return report(err)
	}
	comboPattern := fmt.Sprintf("(%s)|(%s)", funcPattern, constructorPattern)

	allFunctions, err := findFuncs(pkgPattern, comboPattern, nil, flags)
	if err != nil {
		return report(err)
	}

	// Group by package, and catagorize into candidate funcs and constructors.
	m := make(map[string]*pkg)
	for _, function := range allFunctions {
		p := m[function.PkgPath]
		if p == nil {
			p = &pkg{pkgPath: function.PkgPath}
			m[function.PkgPath] = p
		}
		if funcRe.MatchString(function.FuncName) {
			p.functions = append(p.functions, function)
		}
		if isConstructor(function.TypesFunc) && constructorRe.MatchString(function.FuncName) {
			p.constructors = append(p.constructors, function)
		}
	}

	var pkgs []*pkg
	for _, p := range m {
		pkgs = append(pkgs, p)
		// put constructors a deterministic order.
		// TODO: for now, we'll prefer simpler constructors as approximated by length (so 'New' before 'NewSomething').
		sort.Slice(p.constructors, func(i, j int) bool {
			if len(p.constructors[i].FuncName) < len(p.constructors[j].FuncName) {
				return true
			}
			if len(p.constructors[i].FuncName) == len(p.constructors[j].FuncName) {
				return p.constructors[i].FuncName < p.constructors[j].FuncName
			}
			return false
		})
	}

	sort.Slice(pkgs, func(i, j int) bool {
		return pkgs[i].pkgPath < pkgs[j].pkgPath
	})

	return pkgs, nil
}

// findFuncs searches for requested functions matching a package pattern and func pattern.
// TODO: this is a temporary fork from fzgo/fuzz.FindFunc.
// TODO: maybe change flags to a predicate function?
func findFuncs(pkgPattern, funcPattern string, env []string, flags findFuncFlag) ([]mod.Func, error) {
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
		pkgDir := ""
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
					if len(result) > 0 && flags&flagMultiMatch == 0 {
						return nil, fmt.Errorf("multiple matches not allowed. multiple matches for pattern %v and func %v: %v.%v and %v.%v",
							pkgPattern, funcPattern, pkg.PkgPath, id.Name, result[0].PkgPath, result[0].FuncName)
					}
					if pkgDir == "" {
						pkgDir, err = goListDir(pkg.PkgPath, env)
						if err != nil {
							return nil, report(err)
						}
					}

					function := mod.Func{
						FuncName: id.Name, PkgName: pkg.Name, PkgPath: pkg.PkgPath, PkgDir: pkgDir,
						TypesFunc: f,
					}
					result = append(result, function)
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

// goList returns a list of packages for a package pattern.
// There is probably a more refined way to do this, but it might do 'go list' anyway.
func goList(dir string, args ...string) ([]string, error) {
	if dir == "" {
		dir = "."
	}

	cmdArgs := append([]string{"list"}, args...)
	cmd := exec.Command("go", cmdArgs...)
	cmd.Env = os.Environ()
	cmd.Stderr = os.Stderr
	cmd.Dir = dir

	out, err := cmd.Output()
	if err != nil {
		// If this fails with a pkgPath as empty string, check packages.Config.Mode
		fmt.Fprintf(os.Stderr, "fzgen: 'go list' failed for args %q:\n%s\n", args, string(out))
		return nil, fmt.Errorf("failed to find package for args %q: %v", args, err)
	}

	var result []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		result = append(result, line)
	}
	return result, nil
}

// isInModule reports if dir appears to be within a module with a 'go.mod'.
func isInModule(dir string) (bool, error) {
	cmd := exec.Command("go", "env", "GOMOD")
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.Output()
	if err != nil {
		return false, err
	}
	s := strings.TrimSpace(string(out))
	if s == "" || s == os.DevNull {
		// Go 1.11 reports empty string for no 'go.mod'.
		// Go 1.12+ report os.DevNull for no 'go.mod'
		return false, nil
	}
	return true, nil
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

	n, err := namedType(recv)
	if err != nil {
		// don't treat as fatal error.
		fmt.Fprintf(os.Stderr, "fzgen: warning: failed to determine if exported for receiver %v for func %v: %v\n",
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
	// TODO: this might be redundant check to do both Type() and Type().Underlying(), but shouldn't hurt.
	_, ok = recv.Type().(*types.Interface)
	if ok {
		return true
	}
	_, ok = recv.Type().Underlying().(*types.Interface)
	return ok
}
