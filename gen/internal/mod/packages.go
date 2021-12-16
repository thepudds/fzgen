package mod

import (
	"fmt"
	"go/types"
)

// Func represents a discovered function that will be fuzzed.
type Func struct {
	FuncName  string
	PkgName   string      // package name (should be the same as the package's package statement)
	PkgPath   string      // import path
	PkgDir    string      // local on-disk directory
	TypesFunc *types.Func // auxiliary information about a Func from the go/types package
}

// FuzzName returns the '<pkg>.<OrigFuzzFunc>' string.
// For example, it might be 'fmt.FuzzFmt'. In fzgo,
// this was used in messages, and as part of the path when creating
// the corpus location under testdata.
func (f *Func) FuzzName() string {
	return fmt.Sprintf("%s.%s", f.PkgName, f.FuncName)
}

func (f *Func) String() string {
	return f.FuzzName()
}
