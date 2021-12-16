// fzgen automatically generates fuzz functions, similar in spirit to cweill/gotests.
//
// For example, if you run fzgen against github.com/google/uuid, it generates
// a uuid_fuzz.go file with 30 or so functions like:
//
//   func Fuzz_UUID_MarshalText(u1 uuid.UUID) {
// 	   u1.MarshalText()
//   }
//
//   func Fuzz_UUID_UnmarshalText(u1 *uuid.UUID, data []byte) {
// 	   if u1 == nil {
// 		 return
// 	   }
// 	   u1.UnmarshalText(data)
//   }
//
// You can then edit or delete indivdual fuzz funcs as desired, and then fuzz
// using the rich signature fuzzing support in thepudds/fzgo, such as:
//
//  fzgo test -fuzz=. ./...
package fzgen

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

// one way to test this is against the stdlib (here, this just tests that fzgen generates and the result compiles successfully):
//   for x in $(go list std | egrep -v 'internal|runtime|unsafe|vendor|image/color/palette'); do start=$(pwd); echo $x; mkdir -p $x; cd $x ; fzgen $x && gotip test . || echo "--- FAILED $x ---"; cd $start; done &> out.txt
// current stats:
//   grep -r '^func Fuzz' | wc -l
//   2775
//   grep -r 'skipping' | wc -l
//   603

// Usage contains short usage information.
var Usage = `
Usage:
	fzgen [-chain] [-parallel] [-ctor=<target-constructor-regexp>] [-unexported] [pkg]
	
Running fzgen without any arguments targets the package in the current directory.

fzgen outputs a set of wrapper fuzz functions for all functions matching
the -func regexp, which defaults to matching all functions. The target package
defaults to the current directory. The target package should be in the current 
module or listed as dependency of the current module (e.g., via 'go get example.com/foo').

The resulting wrapper functions will all start with 'Fuzz', and are candidates 
for use with fuzzing via Go 1.18 cmd/go (e.g., 'gotip test -fuzz=.').

A package pattern is allowed, but should only match one package.

Test functions and any function that already starts with 'Fuzz' are skipped,
as are functions that have unsupported parameters such as a channel.

`

func FzgenMain() int {
	// handle flags
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, Usage)
		flag.PrintDefaults()
	}

	// Most commonly used:
	chainFlag := flag.Bool("chain", false, "loop over the methods of an object, which requires finding a suitable constructor in the same package and which is controllable via the -ctor flag.")
	parallelFlag := flag.Bool("parallel", false, "indicates an emitted chain can be run in parallel. requires -chain")
	outFileFlag := flag.String("o", "autofuzz_test.go", "output file name. defaults to autofuzz_test.go or autofuzzchain_test.go")
	constructorPatternFlag := flag.String("ctor", "^New", "regexp to use if searching for constructors to automatically use.")

	// Less commonly used:
	funcPatternFlag := flag.String("func", ".", "function regex, defaults to matching all candidate functions")
	unexportedFlag := flag.Bool("unexported", false, "emit wrappers for unexported functions in addition to exported functions")
	qualifyAllFlag := flag.Bool("qualifyall", true, "all identifiers are qualified with package, including identifiers from the target package. "+
		"If the package is '.' or not set, this defaults to false. Else, it defaults to true.")
	constructorFlag := flag.Bool("ctorinject", true, "automatically insert constructors when wrapping a method call "+
		"if a suitable constructor can be found in the same package.")

	flag.Parse()

	var pkgPattern string
	switch {
	case flag.NArg() > 1:
		fmt.Println("fzgen: only one package pattern argument is allowed, and it must match only one package")
		flag.Usage()
		return 2
	case flag.NArg() == 1:
		pkgPattern = flag.Arg(0)
	default:
		pkgPattern = "."
	}

	if *parallelFlag && !*chainFlag {
		fmt.Fprintf(os.Stderr, "fzgen: error: -parallel flag requires -chain")
		return 2
	}

	// search for functions in the requested package that
	// matches the supplied func regex
	options := flagExcludeFuzzPrefix | flagAllowMultiFuzz
	if !*unexportedFlag {
		options |= flagRequireExported
	}
	var qualifyAll bool
	if pkgPattern == "." {
		qualifyAll = false
	} else {
		// qualifyAllFlag defaults to true, which is what we want
		// for non-local package.
		qualifyAll = *qualifyAllFlag
	}

	functions, err := findFunc(pkgPattern, *funcPatternFlag, nil, options)
	if err != nil {
		// TODO: probably return 1 instead in order to work better with testscripts?
		fail(err)
	}

	wrapperOpts := wrapperOptions{
		qualifyAll:         qualifyAll,
		insertConstructors: *constructorFlag,
		constructorPattern: *constructorPatternFlag,
		parallel:           *parallelFlag,
	}

	var out []byte
	if !*chainFlag {
		out, err = emitIndependentWrappers(pkgPattern, functions, wrapperOpts)
	} else {
		out, err = emitChainWrappers(pkgPattern, functions, wrapperOpts)
	}
	if err != nil {
		fail(err)
	}

	if *chainFlag && *outFileFlag == "autofuzz_test.go" {
		*outFileFlag = "autofuzzchain_test.go"
	}
	err = ioutil.WriteFile(*outFileFlag, out, 0o644)
	if err != nil {
		fail(err)
	}
	fmt.Println("fzgen: created", *outFileFlag)

	return 0
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "fzgen: error: %v\n", err)
	os.Exit(1)
}
