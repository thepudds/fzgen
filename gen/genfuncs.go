package fzgen

import (
	"bytes"
	"errors"
	"fmt"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/thepudds/fzgen/fuzzer"
	"github.com/thepudds/fzgen/gen/internal/mod"
	"golang.org/x/tools/imports"
)

type wrapperOptions struct {
	qualifyAll         bool   // qualify all variables with package name
	insertConstructors bool   // attempt to insert suitable constructors when wrapping methods
	constructorPattern string // regexp for searching for candidate constructors
	parallel           bool   // set the Parallel flag in the emitted code, which allows steps of a chain to run in parallel
}

type emitFunc func(format string, args ...interface{})

var errSilentSkip = errors.New("silently skipping wrapper generation")

// emitIndependentWrappers emits fuzzing wrappers where possible for the list of functions passed in.
// It might skip a function if it has no input parameters, or if it has a non-fuzzable parameter
// type such as interface{}.
// See package comment in main.go for more details.
func emitIndependentWrappers(pkgPattern string, functions []mod.Func, options wrapperOptions) ([]byte, error) {
	if len(functions) == 0 {
		return nil, fmt.Errorf("no matching functions found")
	}

	// start by hunting for possible constructors in the same package if requested.
	var possibleConstructors []mod.Func
	if options.insertConstructors {
		// We default to the pattern ^New, but allow user-specified patterns.
		// We don't check the err here because it can be expected to not find anything if there
		// are no functions that start with New (and this is our second call to FindFunc, so
		// other problems should have been reported earlier).
		// TODO: consider related tweak to error reporting in FindFunc?
		possibleConstructors, _ = findFunc(pkgPattern, options.constructorPattern, nil,
			flagExcludeFuzzPrefix|flagAllowMultiFuzz|flagRequireExported)
		// put possibleConstructors into a semi-deterministic order.
		// TODO: for now, we'll prefer simpler constructors as approximated by length (so 'New' before 'NewSomething').
		sort.Slice(possibleConstructors, func(i, j int) bool {
			return len(possibleConstructors[i].FuncName) < len(possibleConstructors[j].FuncName)
		})
	}

	// prepare the output
	buf := new(bytes.Buffer)
	var w io.Writer = buf
	emit := func(format string, args ...interface{}) {
		fmt.Fprintf(w, format, args...)
	}

	// emit the intro material
	var pkgSuffix string
	if options.qualifyAll {
		pkgSuffix = "fuzz // rename if needed"
	}
	emit("package %s%s\n\n", functions[0].TypesFunc.Pkg().Name(), pkgSuffix)
	emit("// if needed, fill in imports or run 'goimports'\n")
	emit("import (\n")
	emit("\t\"testing\"\n")
	emit("\t\"%s\"\n", functions[0].PkgPath)
	emit("\t\"github.com/thepudds/fzgen/fuzzer\"\n")
	emit(")\n\n")

	// put our functions we want to wrap into a deterministic order
	sort.Slice(functions, func(i, j int) bool {
		// types.Func.String outputs strings like:
		//   func (github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection.A).ValMethodWithArg(i int) bool
		// works ok for clustering results, though pointer receiver and non-pointer receiver methods don't cluster.
		// could strip '*' or sort another way, but probably ok, at least for now.
		return functions[i].TypesFunc.String() < functions[j].TypesFunc.String()
	})

	// loop over our the functions we are wrapping, emitting a wrapper where possible.
	for _, function := range functions {
		err := emitIndependentWrapper(emit, function, possibleConstructors, options.qualifyAll)
		if errors.Is(err, errSilentSkip) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("error processing %s: %v", function.FuncName, err)
		}
	}

	// fix up any needed imports.
	// TODO: perf: this seems slower than expected. Check what style of path should be used for filename?
	// imports.Process has this comment:
	//   Note that filename's directory influences which imports can be chosen,
	//   so it is important that filename be accurate.
	filename, err := filepath.Abs(("autofuzz_test.go"))
	warn := func(err error) {
		fmt.Fprintln(os.Stderr, "genfuzzfuncs: warning: continuing after failing to automatically adjust imports:", err)
	}
	if err != nil {
		warn(err)
		return buf.Bytes(), nil
	}
	out, err := imports.Process(filename, buf.Bytes(), nil)
	if err != nil {
		warn(err)
		return buf.Bytes(), nil
	}
	return out, nil
}

// paramRepr contains string representations of inputParams to the wrapper function that we are
// creating. It includes params for the function under test, as well as in some cases
// args for a related constructor.
type paramRepr struct {
	paramName string
	typ       string
	v         *types.Var
}

// emitIndependentWrapper emits one fuzzing wrapper if possible.
// It takes a list of possible constructors to insert into the wrapper body if the
// constructor is suitable for creating the receiver of a wrapped method.
// qualifyAll indicates if all variables should be qualified with their package.
func emitIndependentWrapper(emit emitFunc, function mod.Func, possibleConstructors []mod.Func, qualifyAll bool) error {
	f := function.TypesFunc
	wrappedSig, ok := f.Type().(*types.Signature)
	if !ok {
		return fmt.Errorf("function %s is not *types.Signature (%+v)", function, f)
	}
	localPkg := f.Pkg()

	// Set up types.Qualifier funcs we can use with the types package
	// to scope variables by a package or not.
	defaultQualifier, localQualifier := qualifiers(localPkg, qualifyAll)

	// Get our receiver, which might be nil if we don't have a receiver
	recv := wrappedSig.Recv()

	// Determine our wrapper name, which includes the receiver's type if we are wrapping a method.
	var wrapperName string
	var err error
	if recv == nil {
		wrapperName = fmt.Sprintf("Fuzz_%s", f.Name())
	} else {
		n, err := findReceiverNamedType(recv)
		if err != nil {
			// output to stderr, but don't treat as fatal error.
			fmt.Fprintf(os.Stderr, "genfuzzfuncs: warning: createWrapper: failed to determine receiver type: %v: %v\n", recv, err)
			return nil
		}
		recvNamedTypeLocalName := types.TypeString(n.Obj().Type(), localQualifier)
		wrapperName = fmt.Sprintf("Fuzz_%s_%s", recvNamedTypeLocalName, f.Name())
	}

	// Start building up our list of parameters we will use in input
	// parameters to the new wrapper func we are about to emit.
	var inputParams []*types.Var

	// Check if we have a receiver for the function under test (that is, testing a method)
	// and then see if we can replace the receiver by finding
	// a suitable constructor and "promoting" the constructor's arguments up into the wrapper's parameter list.
	//
	// The end result is rather than emitting a wrapper like so for strings.Reader.Read:
	// 		f.Fuzz(func(t *testing.T, r *strings.Reader, b []byte) {
	// 			r.Read(b)
	// 		})
	//
	// Instead of that, if we find a suitable constructor for the wrapped method's receiver 'r',
	// we (optionally) instead insert a call to the constructor,
	// and "promote" up the constructor's args into the fuzz wrapper's parameters:
	// 		f.Fuzz(func(t *testing.T, s string, b []byte) {
	// 			r := strings.NewReader(s)
	// 			r.Read(b)
	// 		})
	var ctorReplace ctorMatch
	if recv != nil {
		if recv.Name() == "" {
			// this can be an interface method. skip, nothing to do here.
			return errSilentSkip
		}
		var paramsToAdd []*types.Var
		ctorReplace, paramsToAdd, err = constructorReplace(recv, possibleConstructors)
		if err != nil {
			return err
		}
		inputParams = append(inputParams, paramsToAdd...)
	}

	// Also add in the parameters for the function under test.
	for i := 0; i < wrappedSig.Params().Len(); i++ {
		v := wrappedSig.Params().At(i)
		inputParams = append(inputParams, v)
	}
	if len(inputParams) == 0 {
		// skip this wrapper, not useful for fuzzing if no inputs (no receiver, no parameters).
		return errSilentSkip
	}

	var paramReprs []paramRepr
	for i, v := range inputParams {
		typeStringWithSelector := types.TypeString(v.Type(), defaultQualifier)
		paramName := avoidCollision(v, i, localPkg, inputParams)
		paramReprs = append(paramReprs, paramRepr{paramName: paramName, typ: typeStringWithSelector, v: v})
	}

	// Check if we have an interface or function pointer in our desired parameters,
	// which we can't fill with values during fuzzing.
	support := checkParamSupport(emit, inputParams, wrapperName)
	if support == noSupport {
		// skip this wrapper. disallowedParams emitted a comment with more details.
		return errSilentSkip
	}

	// Start emitting the wrapper function!
	// Start with the func declaration and the start of f.Fuzz.
	emit("func %s(f *testing.F) {\n", wrapperName)
	emit("\tf.Fuzz(func(t *testing.T, ")

	switch support {
	case nativeSupport:
		// The result for this line will end up similar to:
		//    f.Fuzz(func(t *testing.T, s string, i int) {
		// Iterate over the our input parameters and emit.
		// If we are a method, this includes either an object that is wrapped receiver's type,
		// or it includes the parameters for a constructor if we found a suitable one.
		for i, p := range paramReprs {
			// want: foo string, bar int
			if i > 0 {
				// need a comma if something has already been emitted
				emit(", ")
			}
			emit("%s %s", p.paramName, p.typ)
		}
		emit(") {\n")

		// Always crashing on a nil receiver is not particularly interesting, so emit the code to avoid.
		// Also avoid nil crash if we have any other pointer parameters.
		// A user can easliy delete all or part this boilerplate if they don't want particular nil checks.
		emitNilChecks(emit, inputParams, localPkg)
	case fillRequired:
		// This is something not yet supported by cmd/go, but we can shim it via fzgen.
		// The result will up similar to:
		//    f.Fuzz(func(t *testing.T, data []byte) {
		//    var m map[string]int
		//    fz := fuzzer.NewFuzzer(data)
		//    fz.Fill(&map)
		// First, finish the line we are on.
		emit("data []byte) {\n")
		// Second, declare the variables we need to fill.
		for _, p := range paramReprs {
			emit("\t\tvar %s %s\n", p.paramName, p.typ)
		}
		// Third, create a fzgen.Fuzzer
		emit("\t\tfz := fuzzer.NewFuzzer(data)\n")
		// Fourth, emit a potentially wide Fill call for all the variables we declared.
		emit("\t\tfz.Fill(")
		for i, p := range paramReprs {
			if i > 0 {
				// need a comma if something has already been emitted
				emit(", ")
			}
			emit("&%s", p.paramName)
		}
		emit(")\n")
		// Avoid nil crash if we have pointer parameters.
		emitNilChecks(emit, inputParams, localPkg)
		emit("\n")
	default:
		panic(fmt.Sprintf("unexpected result from checkParamSupport: %v", support))
	}

	// Emit a constructor if we have one.
	// collisionOffset tracks how far we are into the parameters of the final fuzz function signature.
	// (For a constructor call, it will be zero because for the final fuzz function,
	// the signature starts with any constructor parameters. For the function under test,
	// the offset will by the length of the signature of constructor, if any, or zero if no constructor.
	// This is because the parameters for the function under test follow any constructor parameters
	// in the final fuzz function signature.
	// TODO: collisionOffset is a bit quick & dirty. Probably should track a more direct
	// (original name, provenance) -> new name mapping, or perhaps simplify the logic
	// so that we never use original names.
	collisionOffset := 0
	if recv != nil {
		if ctorReplace.sig != nil {
			// insert our constructor!
			emit("\t%s", avoidCollision(recv, 0, localPkg, inputParams))
			if ctorReplace.secondResultIsErr {
				emit(", err")
			}
			emit(" := ")
			if qualifyAll {
				emit("%s.%s(", localPkg.Name(), ctorReplace.f.Name())
			} else {
				emit("%s(", ctorReplace.f.Name())
			}
			emitArgs(emit, ctorReplace.sig, 0, localPkg, inputParams)
			emit(")\n")
			if ctorReplace.secondResultIsErr {
				emit("\tif err != nil {\n")
				emit("\t\treturn\n")
				emit("\t}\n")
			}
			collisionOffset = ctorReplace.sig.Params().Len()
		} else {
			// We have a receiver, but we are not injecting a constructor (perhaps because
			// the option was disabled, or perhaps because we did not find a suitable constructor)
			// Reserve space in our naming space for the receiver.
			// TODO: we test this case, but add comment here describing which test would fail.
			collisionOffset = 1
		}
	}

	// Emit the call to the wrapped function.
	emitWrappedFunc(emit, f, wrappedSig, "", collisionOffset, qualifyAll, inputParams, localPkg)
	emit("\t})\n")
	emit("}\n\n")

	return nil
}

// emitNilChecks emits checks for nil for our input parameters.
// Always crashing on a nil receiver is not particularly interesting, so emit the code to avoid.
// Also check if we have any other pointer parameters.
// A user can decide to delete if they want to test nil recivers or nil parameters.
// Also, could have a flag to disable.
func emitNilChecks(emit emitFunc, allParams []*types.Var, localPkg *types.Package) {
	foundPointer := false

	for i, v := range allParams {
		_, ok := v.Type().(*types.Pointer)
		if ok {
			if !foundPointer { // first
				foundPointer = true
				emit("\tif ")
			} else { // second or later
				emit("|| ")
			}
			paramName := avoidCollision(v, i, localPkg, allParams)
			emit("%s == nil", paramName)
		}
	}
	if foundPointer {
		emit(" {\n")
		emit("\t\treturn\n")
		emit("\t}\n")
	}
}

// emitWrappedFunc emits the call to the function under test.
// A target that is not "" indicates the caller wants to use a
// specific target name in place of any receiver name.
// For example, a target set to "target" would result in "target.Load(key)".
func emitWrappedFunc(emit emitFunc, f *types.Func, wrappedSig *types.Signature, target string, collisionOffset int, qualifyAll bool, allParams []*types.Var, localPkg *types.Package) {
	recv := wrappedSig.Recv()
	switch {
	case recv != nil && target != "":
		// Use target in place of the existing receiver, only doing this when we have a receiver.
		// (If there is no receiver, target isn't useful).
		emit("\t%s.%s(", target, f.Name())
	case recv != nil:
		recvName := avoidCollision(recv, 0, localPkg, allParams)
		emit("\t%s.%s(", recvName, f.Name())
	case qualifyAll:
		emit("\t%s.%s(", localPkg.Name(), f.Name())
	default:
		emit("\t%s(", f.Name())
	}
	// emit the arguments to the wrapped function.
	emitArgs(emit, wrappedSig, collisionOffset, localPkg, allParams)
	emit(")\n")
}

// emitArgs emits the arguments needed to call a signature, including handling renaming arguments
// based on collisions with package name or other parameters.
func emitArgs(emit emitFunc, sig *types.Signature, collisionOffset int, localPkg *types.Package, allWrapperParams []*types.Var) {
	for i := 0; i < sig.Params().Len(); i++ {
		v := sig.Params().At(i)
		paramName := avoidCollision(v, i+collisionOffset, localPkg, allWrapperParams)
		if i > 0 {
			emit(", ")
		}
		emit(paramName)
	}
	if sig.Variadic() {
		// last argument needs an elipsis
		emit("...")
	}
}

type paramSupport uint

const (
	noSupport     paramSupport = iota // we don't yet support it at all
	fillRequired                      // not supported by underlying fuzzing engine, but we support it via fz.Fill
	nativeSupport                     // supported natively by underlying fuzzing engine
	unknown
)

// checkParamSupport reports the level of support across the input parameters.
// It stops checking if it finds a param that is noSupport.
// TODO: this is currently focuses on excluding the most common problems, and defaults to trying nativeSupport (which might cause cmd/go to complain).
func checkParamSupport(emit emitFunc, allWrapperParams []*types.Var, wrapperName string) paramSupport {
	res := unknown
	if len(allWrapperParams) == 0 {
		// An easy case that is handled by cmd/go is no params at all.
		// This doesn't currently happen with independent wrappers, but does happen with chain wrappers
		// that are targeting a method with no params.
		return nativeSupport
	}
	min := func(a, b paramSupport) paramSupport {
		// TODO: use generics in 1.18 ;-)
		if a < b {
			return a
		}
		return b
	}
	for _, v := range allWrapperParams {
		// basic checking for interfaces, funcs, or pointers or slices of interfaces or funcs.
		// TODO: should do a more comprehensive check, perhaps recursive, including handling cycles, but keep it simple for now.
		// TODO: alt, invert this to check for things we believe cmd/go supports and disallow things we know we can't fill?
		// TODO: I think cmd/go does support not pointers like *int or ***int? And not yet maps or slices outside of []byte?
		t := v.Type()
		t = stripPointers(t, 0)
		if t != v.Type() {
			// Stripped at least one pointer. Mark that we will need to fill *if* the other checks also pass,
			// but we know our best case is to fill (thoug we might also mark noSupport down below after the other checks).
			res = min(fillRequired, res)
		}

		// TODO: I thought cmd/go supported named types like MyInt, but seemingly not. Add quick check here, which should
		// give correct result, but leave rest of logic as is for now (even though some is redundant w/ this check).
		if t != t.Underlying() {
			res = min(fillRequired, res)
		}

		// Switch to check if we might be able to fill this type.
		switch u := t.Underlying().(type) {
		case *types.Slice:
			t = u.Elem()
			tt, ok := t.(*types.Basic)
			if ok && tt.Kind() == types.Byte {
				res = min(nativeSupport, res) // TODO: does cmd/go support more slices than []byte?
			} else {
				res = min(fillRequired, res)
			}
		case *types.Array:
			t = u.Elem()
			res = min(fillRequired, res)
		case *types.Map:
			t = u.Elem() // basic attempt to check for something like map[string]io.Reader below.
			res = min(fillRequired, res)
		case *types.Struct:
			res = min(fillRequired, res)
		case *types.Basic:
			switch u.Kind() {
			case types.Uintptr, types.UnsafePointer, types.Complex64, types.Complex128:
				// fz.Fill handles complex, and fills Uintptr and UnsafePointer with nil, which is hopefully reasonable choice.
				res = min(fillRequired, res)
			}
		}

		// We might have updated t above. Switch to check if t is unsupported
		// (which might have been an Elem of a slice or map, etc..)
		switch t.Underlying().(type) {
		case *types.Interface:
			if !fuzzer.SupportedInterfaces[t.String()] {
				emit("// skipping %s because parameters include unsupported interface: %v\n\n", wrapperName, v.Type())
				res = min(noSupport, res)
				return res
			}
			res = min(fillRequired, res)
		case *types.Signature, *types.Chan:
			emit("// skipping %s because parameters include unsupported func or chan: %v\n\n", wrapperName, v.Type())
			res = min(noSupport, res)
			return res
		}

		// If we didn't easily find a problematic type above, we'll guess that cmd/go supports it,
		// and let cmd/go complain if it needs to for more complex cases not handled above.
		res = min(nativeSupport, res)
	}
	return res
}

// ctorMatch holds the signature of a suitable constructor if we found one.
// We use the signature to "promote" the needed arguments from the constructor
// parameter list up to the wrapper function parameter list.
// Sig is nil if a suitable constructor was not found.
type ctorMatch struct {
	sig               *types.Signature
	f                 *types.Func
	ctorResultN       *types.Named // TODO: no longer need this, probably
	secondResultIsErr bool
}

// constructorReplace determines if there is a constructor we can replace,
// and returns that constructor along with the related parameters we need to
// add to the main wrapper method. They will either be the parameters
// needed to pass into the constructor, or it will be a single parameter
// corresponding to the wrapped method receiver if we didn't find a usable constructor.
func constructorReplace(recv *types.Var, possibleCtors []mod.Func) (ctorMatch, []*types.Var, error) {
	var match ctorMatch
	var err error
	var paramsToAdd []*types.Var
	for _, possibleCtor := range possibleCtors {
		match, err = constructorMatch(recv, possibleCtor)
		if err != nil {
			return ctorMatch{}, nil, err
		}
		if match.sig != nil {
			// stop our search, and insert our constructor's arguments.
			for i := 0; i < match.sig.Params().Len(); i++ {
				v := match.sig.Params().At(i)
				paramsToAdd = append(paramsToAdd, v)
			}
			return match, paramsToAdd, nil
		}
	}

	// we didn't find a matching constructor,
	// so the method receiver will be added to the wrapper function's parameters.
	paramsToAdd = append(paramsToAdd, recv)
	return match, paramsToAdd, nil
}

// constructorMatch determines if a receiver for a possible method
// under test has a matching type with a constructor.
// It compares the named types, and allows a match if the constructor
// has a single return value, or two return values with an error type as the second.
func constructorMatch(recv *types.Var, possibleCtor mod.Func) (ctorMatch, error) {
	ctorSig, ok := possibleCtor.TypesFunc.Type().(*types.Signature)
	if !ok {
		return ctorMatch{}, fmt.Errorf("function %s is not *types.Signature (%+v)",
			possibleCtor, possibleCtor.TypesFunc)
	}

	// TODO: we used to disallow ctors here with ctorSig.Params().Len() == 0, but probably OK to allow?

	ctorResults := ctorSig.Results()
	if ctorResults.Len() > 2 || ctorResults.Len() == 0 {
		return ctorMatch{}, nil
	}
	secondResultIsErr := false
	if ctorResults.Len() == 2 {
		// We allow error type as second return value
		secondResult := ctorResults.At(1)
		_, ok = secondResult.Type().Underlying().(*types.Interface)
		if ok && secondResult.Type().String() == "error" {
			secondResultIsErr = true
		} else {
			return ctorMatch{}, nil
		}
	}

	ctorResult := ctorResults.At(0)

	recvN, err := findReceiverNamedType(recv)
	if err != nil {
		// output to stderr, but don't treat as fatal error.
		fmt.Fprintf(os.Stderr, "genfuzzfuncs: warning: constructorReplace: failed to determine receiver type when looking for constructors: %v: %v\n", recv, err)
		return ctorMatch{}, nil
	}

	// TODO: ctorResult here is not a receiver. probably rename findReceiverNamedType to be more general.
	ctorResultN, err := findReceiverNamedType(ctorResult)
	if err != nil {
		// findReceiverNamedType returns a types.Named if the passed in
		// types.Var is a types.Pointer or already types.Named.
		// This candidate constructor is neither of those, which means we can't
		// use it to give us the type we need for the receiver for this method we are trying to fuzz.
		// This is not an error for matching purposes. It just means it didn't match.
		return ctorMatch{}, nil
	}

	// TODO: this is old & very early code... is there some reason we can't compare types.Var.Type() more directly?
	// TODO (old): types.Identical wasn't working as expected. Imperfect fall back for now.
	// types.TypeString(recvN, nil) returns a fully exanded string that includes the import path, e.g.,:
	//   github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection.A
	if types.TypeString(recvN, nil) == types.TypeString(ctorResultN, nil) {
		// we found a match between this constructor's return type and the receiver type
		// we need for the method we are trying to fuzz! (ignoring a pointer, which we stripped off above).
		match := ctorMatch{
			sig:               ctorSig,
			f:                 possibleCtor.TypesFunc,
			ctorResultN:       ctorResultN,
			secondResultIsErr: secondResultIsErr,
		}
		return match, nil
	}

	// We didn't find a match
	return ctorMatch{}, nil
}

// avoidCollision takes a variable (which might correpsond to a parameter or argument),
// and returns a non-colliding name, or the original name, based on
// whether or not it collided with package name or other with parameters.
func avoidCollision(v *types.Var, i int, localPkg *types.Package, allWrapperParams []*types.Var) string {
	// handle corner case of using the package name as a parameter name (e.g., flag.UnquoteUsage(flag *Flag)),
	// or two parameters of the same name (e.g., if one was from a constructor and the other from the func under test).
	paramName := v.Name()

	if paramName == "_" || paramName == "" {
		// treat all underscore or unnamed identifiers as colliding, and use something like "_x1" or "_x2" in their place.
		// this avoids 'cannot use _ as value' errors for things like 'NotNilFilter(_ string, v reflect.Value)' stdlib ast package.
		// an alternative would be to elide them when possible, but easier to retain, at least for now.
		return fmt.Sprintf("_x%d", i+1)
	}

	collision := false
	switch paramName {
	case localPkg.Name(), "t", "f", "fz", "data", "target", "steps", "result1", "result2", "tmp1", "tmp2":
		// avoid the common variable names for testing.T, testing.F, fzgen.Fuzzer,
		// as well as variables we might emit (preferring an aesthetically pleasing
		// name for something like "steps" in the common case over preserving
		// a rare use of "steps" by a wrapped func).
		collision = true
	default:
		for _, p := range allWrapperParams {
			if v != p && paramName == p.Name() {
				collision = true
				break
			}
		}
	}
	if collision {
		// TODO: could check again to see if this also collisde,
		// but maybe find an example where it matters first (no examples across 3K+ stdlib funcs).
		paramName = fmt.Sprintf("%s%d", string([]rune(paramName)[0]), i+1)
	}
	return paramName
}

// qualifiers sets up a types.Qualifier func we can use with the types package,
// paying attention to whether we are qualifying everything or not.
func qualifiers(localPkg *types.Package, qualifyAll bool) (defaultQualifier, localQualifier types.Qualifier) {
	localQualifier = func(pkg *types.Package) string {
		// We call pkg.Path() here because in some cases, such as the Options type from:
		//    fzgen -func=Close$ -qualifyall=false tailscale.com/logtail/filch
		// two packages that appear to be equal and have the same internal path field do not
		// have pointer equality.
		// The prior problem was the Options type would be emitted as 'filch.Options',
		// rather than the expected 'Options'. Comparing paths here resolves that.
		// TODO: understand better why two *Types.packages with same path do not have pointer equality.
		// TODO: consider using types.RelativeTo, though that also does pointer equality test.
		if pkg.Path() == localPkg.Path() {
			return ""
		}
		return pkg.Name()
	}
	if qualifyAll {
		defaultQualifier = externalQualifier
	} else {
		defaultQualifier = localQualifier
	}
	return defaultQualifier, localQualifier
}

// externalQualifier can be used as types.Qualifier in calls to types.TypeString and similar.
func externalQualifier(p *types.Package) string {
	// always return the package name, which
	// should give us things like pkgname.SomeType
	return p.Name()
}

func stripPointers(t types.Type, depth int) types.Type {
	if depth > 10 {
		return t // TODO: not sure we need depth, but we'll play it safe for now.
	}
	depth++
	u, ok := t.Underlying().(*types.Pointer)
	if !ok {
		return t
	}
	return stripPointers(u.Elem(), depth)
}

// findReceiverNamedType returns a types.Named if the passed in
// types.Var is a types.Pointer or already types.Named.
func findReceiverNamedType(recv *types.Var) (*types.Named, error) {
	reportErr := func() (*types.Named, error) {
		return nil, fmt.Errorf("expected pointer or named type: %+v", recv.Type())
	}

	switch t := recv.Type().(type) {
	case *types.Pointer:
		if t.Elem() == nil {
			return reportErr()
		}
		n, ok := t.Elem().(*types.Named)
		if ok {
			return n, nil
		}
	case *types.Named:
		return t, nil
	}
	return reportErr()
}
