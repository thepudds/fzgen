package modulefuzz

import "golang.org/x/mod/module"

// Automatically generated via:
//    genfuzzfuncs -pkg=golang.org/x/mod/module > module_fuzz.go
//    goimports -w module_fuzz.go
// You can then fuzz these rich signatures via:
//    fzgo test -fuzz=.

func Fuzz_Sort(list []module.Version) {
	module.Sort(list)
}

func Fuzz_Version_String(m module.Version) {
	m.String()
}

func Fuzz_Check(path string, version string) {
	module.Check(path, version)
}

func Fuzz_CanonicalVersion(v string) {
	module.CanonicalVersion(v)
}

func Fuzz_CheckFilePath(path string) {
	module.CheckFilePath(path)
}

func Fuzz_CheckImportPath(path string) {
	module.CheckImportPath(path)
}

func Fuzz_CheckPath(path string) {
	module.CheckPath(path)
}

func Fuzz_EscapePath(path string) {
	module.EscapePath(path)
}

func Fuzz_EscapeVersion(v string) {
	module.EscapeVersion(v)
}

func Fuzz_MatchPathMajor(v string, pathMajor string) {
	module.MatchPathMajor(v, pathMajor)
}

func Fuzz_SplitPathVersion(path string) {
	module.SplitPathVersion(path)
}

func Fuzz_UnescapePath(escaped string) {
	module.UnescapePath(escaped)
}

func Fuzz_UnescapeVersion(escaped string) {
	module.UnescapeVersion(escaped)
}
