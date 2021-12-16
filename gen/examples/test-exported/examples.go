package fuzzwrapexamples

import "io"

// ---- Export examples/tests ----

// FuncExported is a test function to make sure we emit exported functions.
func FuncExported(i int)    {}
func funcNotExported(i int) {}

type typeNotExported int

func (t *typeNotExported) pointerRcvNotExportedMethod(i int)   {}
func (t typeNotExported) nonPointerRcvNotExportedMethod(i int) {}
func (t *typeNotExported) PointerExportedMethod(i int)         {}
func (t typeNotExported) NonPointerExportedMethod(i int)       {}

// TypeExported is a test type to make sure we emit exported methods.
type TypeExported int

func (t *TypeExported) pointerRcvNotExportedMethod(i int)   {}
func (t TypeExported) nonPointerRcvNotExportedMethod(i int) {}
func (t *TypeExported) PointerExportedMethod(i int)         {}
func (t TypeExported) NonPointerExportedMethod(i int)       {}

var ExportedFuncVar = func(i int) {}
var notExportedFuncVar = func(i int) {}

// ---- Interface examples/tests ----

// ExportedInterface is a test interface to make sure
// we don't emit anything for the declaration of an interface.
type ExportedInterface interface {
	ExportedFunc()
}

// FuncExportedUsesUnsupportedInterface is a test func to make sure
// we don't emit a wrapper for functions that use unsupported interfaces.
func FuncExportedUsesUnsupportedInterface(e ExportedInterface) {}

// FuncExportedUsesSupportedInterface is a test func to make sure
// we do emit a wrapper for functions that use supported interfaces.
func FuncExportedUsesSupportedInterface(w io.Reader) {}
