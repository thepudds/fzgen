package fuzzwrapexamples

import "bufio"

// ---- Constructor injection examples/tests ----

// When fuzzing a method, by default genfuzzfuncs puts the receiver's
// type into the parameter list of the wrapper function.
// This works reasonably well if the receiver's type has public
// member variables -- we can set and mutate public member variables while fuzzing.
// However, that works less well if there are no public member variables,
// such as for regex.Regexp.
// If asked, we can inject constructors like so:
//   * we determine the type of the receiver for the method we want to fuzz.
//   * we look for a constructor capable of creating the receiver's type.
//   * we "promote" the parameters from the constructor into the params for the wrapper function.
//   * we insert a call to the constructor using those params.
//   * we use the result of the constructor to call method we want to fuzz.

type A struct{ c int }

func NewAPtr(c int) *A                   { return &A{c} }
func (r *A) PtrMethodWithArg(i int) bool { return r.c == i }
func (r *A) PtrMethodNoArg() bool        { return r.c == 0 }
func (r A) ValMethodWithArg(i int) bool  { return r.c == i }
func (r A) ValMethodNoArg() bool         { return r.c == 0 }

type B struct{ c int }

func NewBVal(c int) B                    { return B{c} }
func (r *B) PtrMethodWithArg(i int) bool { return r.c == i }
func (r *B) PtrMethodNoArg() bool        { return r.c == 0 }
func (r B) ValMethodWithArg(i int) bool  { return r.c == i }
func (r B) ValMethodNoArg() bool         { return r.c == 0 }

// Package is roughly modeled on go/types.Package,
// which has a collision between a parameter name used for
// for the constructor and a parameter name used in a later function
// under test. (The colliding parameter name happens to be 'name',
// though the actual name doesn't matter -- just that it collides).
type Package struct {
	path string
	name string
}

func NewPackage(path, name string) *Package {
	return &Package{path: path, name: name}
}

func (pkg *Package) SetName(name string) { pkg.name = name }

// Reader is roughly modeled on textproto.Reader
// We want to avoid generating a mismatched object variable name:
//		func Fuzz_Reader_ReadLine(r *bufio.Reader) {
//			if r == nil {
//					return
//			}
//			r1 := textproto.NewReader(r)
//			r2.ReadLine()
//		}

type Z struct{}

func NewZ(z *bufio.Reader) *Z {
	return &Z{}
}

func (z *Z) ReadLine() (string, error) {
	return "", nil
}

// Reader is roughly modeled on google/uuid NullUUID.UnmarshalBinary
// We want to avoid generating a mismatched object variable name:

type MyNullUUID struct{}

func (nu *MyNullUUID) UnmarshalBinary(data []byte) error { return nil }

// MyRegexp is roughly modeled on regexp.Expand
type MyRegexp struct{}

func (re *MyRegexp) Expand(dst []byte, template []byte, src []byte, match []int) []byte {
	return nil
}

// Similar to regexp.Compile, let's return an err here
func NewMyRegexp(a int) (*MyRegexp, error) {
	return &MyRegexp{}, nil
}
