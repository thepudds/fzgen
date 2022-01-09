package gen

import (
	"bytes"
	"errors"
	"fmt"
	"go/types"
	"io"
	"os"
	"sort"

	"github.com/thepudds/fzgen/gen/internal/mod"
)

// emitChainWrappers emits a set of fuzzing wrappers where possible for the list of functions passed in.
// Each wrapper consists of a target from a constructor and a set of steps that include invoking methods on the target.
// It might skip a function if it has no input parameters, or if it has a non-fuzzable parameter
// type such as interface{}.
func emitChainWrappers(pkgPath string, pkgFuncs *pkg, wrapperPkgName string, options wrapperOptions) ([]byte, error) {
	possibleConstructors := pkgFuncs.constructors
	if len(possibleConstructors) == 0 {
		return nil, errNoConstructorsMatch
	}

	// Build a map from the receiver type to a set of possible constructors
	// and possible steps with the same receiver type.
	type chain struct {
		recvType     string
		constructors []mod.Func
		steps        []mod.Func
	}
	recvTypes := make(map[string]*chain)
	for _, function := range pkgFuncs.functions {
		// recvN will be the named type if the receiver is a pointer receiver.
		recvN := receiver(function.TypesFunc)
		if recvN == nil {
			continue
		}
		recvType := types.TypeString(recvN, nil)
		c := recvTypes[recvType]
		if c == nil {
			c = &chain{recvType: recvType}
			recvTypes[recvType] = c
		}
		c.steps = append(c.steps, function)
	}

	if len(recvTypes) == 0 {
		return nil, errNoMethodsMatch
	}

	for _, constructor := range possibleConstructors {
		if !isConstructor(constructor.TypesFunc) {
			continue
		}
		// ctorResultN will be the named type if the returned type is a pointer to a named type.
		ctorResultN, _ := constructorResult(constructor.TypesFunc)
		if ctorResultN == nil {
			// Not a named return result, so can't be a constructor.
			continue
		}
		ctorType := types.TypeString(ctorResultN, nil)
		c := recvTypes[ctorType]
		if c == nil {
			// No methods found in loop above for this named type, so nothing to do with this possible constructor.
			continue
		}
		c.constructors = append(c.constructors, constructor)
	}

	// Put our chains in a deterministic order.
	var chains []*chain
	for _, v := range recvTypes {
		chains = append(chains, v)
	}
	sort.Slice(chains, func(i, j int) bool {
		return chains[i].recvType < chains[j].recvType
	})

	// Prepare the output
	buf := new(bytes.Buffer)
	var w io.Writer = buf
	emit := func(format string, args ...interface{}) {
		fmt.Fprintf(w, format, args...)
	}

	// Emit the intro material
	emit("package %s\n\n", wrapperPkgName)
	emit(options.topComment)
	emit("import (\n")
	emit("\t\"testing\"\n")
	if options.qualifyAll {
		emit("\t\"%s\"\n", pkgPath)
	}
	emit("\t\"github.com/thepudds/fzgen/fuzzer\"\n")
	emit(")\n\n")

	// Loop over our chains and emit fuzzing wrappers for each one.
	// We only return an error if all fail.
	var firstErr error
	var success bool
	for _, c := range chains {
		if len(c.constructors) == 0 {
			// No matching constructor.
			// TODO: consider creating new object directly when there is no constructor
			if firstErr == nil {
				firstErr = errNoConstructorsMatch
			}
			continue
		}
		err := emitChainWrapper(emit, c.steps, c.constructors, options)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		if err == nil {
			success = true
		}
	}
	if !success {
		return nil, firstErr
	}

	return buf.Bytes(), nil
}

// emitChainWrapper emits one fuzzing wrapper where possible for the list of functions passed in.
// It might skip a function if it has no input parameters, or if it has a non-fuzzable parameter
// type such as interface{}.
func emitChainWrapper(emit emitFunc, functions []mod.Func, possibleConstructors []mod.Func, options wrapperOptions) error {
	if len(functions) == 0 {
		return errors.New("emitChainWrapper: zero functions")
	}
	if len(possibleConstructors) == 0 {
		return errors.New("emitChainWrapper: zero possible constructors")
	}

	// put possibleConstructors into a semi-deterministic order.
	// TODO: for now, we'll prefer simpler constructors as approximated by length (so 'New' before 'NewSomething').
	sort.Slice(possibleConstructors, func(i, j int) bool {
		return len(possibleConstructors[i].FuncName) < len(possibleConstructors[j].FuncName)
	})

	// use the first constructor
	ctor := possibleConstructors[0]
	err := emitChainTarget(emit, ctor, options.qualifyAll)
	if err != nil {
		return fmt.Errorf("unable to create chain target for constructor %s: %w", ctor.FuncName, err)
	}

	// put our functions we want to wrap into a deterministic order
	sort.Slice(functions, func(i, j int) bool {
		// types.Func.String outputs strings like:
		//   func (github.com/thepudds/fzgo/genfuzzfuncs/examples/test-constructor-injection.A).ValMethodWithArg(i int) bool
		// works ok for clustering results, though pointer receiver and non-pointer receiver methods don't cluster.
		// could strip '*' or sort another way, but probably ok, at least for now.
		return functions[i].TypesFunc.String() < functions[j].TypesFunc.String()
	})

	emit("\tsteps := []fuzzer.Step{\n")

	// loop over our the functions we are wrapping, emitting a wrapper where possible.
	var emittedSteps int
	for _, function := range functions {
		err := emitChainStep(emit, function, ctor, options.qualifyAll)
		if errors.Is(err, errSilentSkip) {
			continue
		}
		if err != nil {
			return fmt.Errorf("error processing %s: %v", function.FuncName, err)
		}
		emittedSteps++
	}
	// close out steps slice
	emit("\t}\n\n")

	if emittedSteps == 0 {
		// TODO: we could handle this better, but let's close out this wrapper in case there is another
		// chain that is useful. The whole output file will be skipped if this was the only candidate chain.
		emit("\t\t_, _, _ = fz, target, steps")
		// close out the f.Fuzz func
		emit("\t})\n")
		// close out test func
		emit("}\n\n")
		return errNoSteps
	}

	// emit the chain func
	emit("\t// Execute a specific chain of steps, with the count, sequence and arguments controlled by fz.Chain\n")
	if !options.parallel {
		emit("\tfz.Chain(steps)\n")
	} else {
		emit("\tfz.Chain(steps, fuzzer.ChainParallel)\n")
	}

	// possibly emit some roundtrip validation checks.
	// TODO: move out to separate func.
	// TODO: make this table-driven, nicer, and handle additional common roundtrip patterns.
	var haveMarshalBinary, haveUnmarshalBinary, haveMarshalText, haveUnmarshalText bool
	for _, flavor := range []string{"Binary", "Text"} {
		for _, function := range functions {
			implements, err := implementsEncodingMarshaler(function.TypesFunc, "Marshal"+flavor)
			if err != nil {
				fmt.Fprintln(os.Stderr, "fzgen: warning: continuing after failing to check encoding.Marshal capabilities:", err)
				continue
			}
			if implements && flavor == "Binary" {
				haveMarshalBinary = true
			}
			if implements && flavor == "Text" {
				haveMarshalText = true
			}
			implements, err = implementsEncodingUnmarshaler(function.TypesFunc, "Unmarshal"+flavor)
			if err != nil {
				fmt.Fprintln(os.Stderr, "fzgen: warning: continuing after failing to check encoding.Unmarshal capabilities:", err)
				continue
			}
			if implements && flavor == "Binary" {
				haveUnmarshalBinary = true
			}
			if implements && flavor == "Text" {
				haveUnmarshalText = true
			}
		}
	}
	var doBinaryRoundtrip, doTextRoundtrip bool
	if haveMarshalText && haveUnmarshalText {
		doTextRoundtrip = true
	}
	if haveMarshalBinary && haveUnmarshalBinary {
		doBinaryRoundtrip = true
	}

	var ctorTypeStringWithSelector string
	if doBinaryRoundtrip || doTextRoundtrip {
		emit("\n// Validate with some roundtrip checks. These can be edited or deleted if not appropriate for your target.")

		// Set up a qualifier so that we handle a local package vs. not for the temp variables
		// for our target.
		// TODO: make utility func, probably.
		localPkg := ctor.TypesFunc.Pkg()
		// Set up types.Qualifier funcs we can use with the types package
		// to scope variables by a package or not.
		defaultQualifier, _ := qualifiers(localPkg, options.qualifyAll)
		ctorType := ctor.TypesFunc.Type()
		ctorSig, ok := ctorType.(*types.Signature)
		if !ok {
			fmt.Fprintln(os.Stderr, "fzgen: warning: continuing after failing to determine type of target for roundtrip checks")
			doBinaryRoundtrip = false
			doTextRoundtrip = false
		}
		ctorResults := ctorSig.Results()
		if ctorResults.Len() < 1 {
			fmt.Fprintln(os.Stderr, "fzgen: warning: skipping roundtrip checks")
			doBinaryRoundtrip = false
			doTextRoundtrip = false
		}
		ctorResult := ctorResults.At(0)
		ctorTypeStringWithSelector = types.TypeString(ctorResult.Type(), defaultQualifier)
	}
	if doTextRoundtrip {
		emit(encodingTextMarshalerRoundtripTmpl, ctorTypeStringWithSelector)
	}
	if doBinaryRoundtrip {
		emit(encodingBinaryMarshalerRoundtripTmpl, ctorTypeStringWithSelector)
	}

	// close out the f.Fuzz func
	emit("\t})\n")

	// close out test func
	emit("}\n\n")

	return nil
}

func emitChainTarget(emit emitFunc, function mod.Func, qualifyAll bool) error {
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
	if recv == nil {
		wrapperName = fmt.Sprintf("Fuzz_%s_Chain", f.Name())
	} else {
		n, err := namedType(recv)
		if err != nil {
			// output to stderr, but don't treat as fatal error.
			fmt.Fprintf(os.Stderr, "fzgen: warning: createWrapper: failed to determine receiver type: %v: %v\n", recv, err)
			return nil
		}
		recvNamedTypeLocalName := types.TypeString(n.Obj().Type(), localQualifier)
		wrapperName = fmt.Sprintf("Fuzz_%s_%s", recvNamedTypeLocalName, f.Name())
	}

	// Start building up our list of parameters we will use in input
	// parameters to the new wrapper func we are about to emit.
	var inputParams []*types.Var

	// Also add in the parameters for the function under test.
	for i := 0; i < wrappedSig.Params().Len(); i++ {
		v := wrappedSig.Params().At(i)
		inputParams = append(inputParams, v)
	}

	paramReprs := make([]paramRepr, len(inputParams))
	for i, v := range inputParams {
		typeStringWithSelector := types.TypeString(v.Type(), defaultQualifier)
		paramName := avoidCollision(v, i, localPkg, inputParams)
		paramReprs[i] = paramRepr{paramName: paramName, typ: typeStringWithSelector, v: v}
	}

	// Check if we have an interface or function pointer in our desired parameters,
	// which we can't fill with values during fuzzing.
	support, unsupportedParam := checkParamSupport(inputParams)
	if support == noSupport {
		// we can't emit this chain target.
		emit("// skipping %s because parameters include func, chan, or unsupported interface: %v\n\n", wrapperName, unsupportedParam)
		return fmt.Errorf("%w: %s takes %s", errUnsupportedParams, function.FuncName, unsupportedParam)
	}

	// Start emitting the wrapper function!
	// Start with the func declaration and the start of f.Fuzz.
	emit("func %s(f *testing.F) {\n", wrapperName)
	emit("\tf.Fuzz(func(t *testing.T, ")

	switch support {
	case nativeSupport, fillRequired:
		// We always want fz := fuzzer.NewFuzzer(data) so that
		// we can call fz.Chain at the bottom of the function we are emitting,
		// so we do the same thing here regardless of whether or not cmd/go
		// natively supports the input args to our constructor.
		// If we also need to do fz.Fill for types that are not natively supported
		// by cmd/go, the result will be similar to:
		//    f.Fuzz(func(t *testing.T, data []byte) {
		//      var m map[string]int
		//      fz := fuzzer.NewFuzzer(data)
		//      fz.Fill(&map)
		// First, finish the line we are on.
		emit("data []byte) {\n")
		// Second, declare the variables we need to fill.
		for _, p := range paramReprs {
			emit("\t\tvar %s %s\n", p.paramName, p.typ)
		}
		// Third, create a fzgen.Fuzzer
		emit("\t\tfz := fuzzer.NewFuzzer(data)\n")

		// Fourth, emit a potentially wide Fill call for any input params for the constructor.
		if len(inputParams) > 0 {
			emit("\t\tfz.Fill(")
			for i, p := range paramReprs {
				if i > 0 {
					// need a comma if something has already been emitted
					emit(", ")
				}
				emit("&%s", p.paramName)
			}
			emit(")\n")
		}

		// Avoid nil crash if we have pointer parameters.
		emitNilChecks(emit, inputParams, localPkg)
		emit("\n")
	default:
		panic(fmt.Sprintf("unexpected result from checkParamSupport: %v", support))
	}

	// Emit the call to the wrapped function, which is the constructor whose result
	// we will reuse in our steps.
	ctorResultN, returnsErr := constructorResult(f)
	if ctorResultN == nil {
		return fmt.Errorf("chain target constructor %s does not return named type (%+v)", f.Name(), f)
	}
	if returnsErr {
		// TODO: instead of "target", would be nicer to reuse receiver variable name here (e.g., from first sample method).
		// If we do that, remove "target" from reserved strings in avoidCollision.
		emit("\ttarget, err := ")
	} else {
		emit("\ttarget := ")
	}
	emitWrappedFunc(emit, f, wrappedSig, "", 0, qualifyAll, inputParams, localPkg)
	if returnsErr {
		emit("\tif err != nil {\n")
		emit("\t\treturn\n")
		emit("\t}\n")
	}
	emit("\n")
	return nil
}

// emitChainStep emits one fuzzing step if possible.
// It takes a list of possible constructors to insert into the step body if the
// constructor is suitable for creating the receiver of a wrapped method.
// qualifyAll indicates if all variables should be qualified with their package.
func emitChainStep(emit emitFunc, function mod.Func, constructor mod.Func, qualifyAll bool) error {
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

	// Determine our wrapper name, which includes the receiver's type if we are wrapping a method,
	// as well as see if the receiver matches the type of our constructor.
	var wrapperName string
	if recv == nil {
		// TODO: could optionally include even if no receiver. For example, uuid.SetNodeID() changes global state, I think.
		// TODO: could include constructors or other funcs that return the chain's targeted type.
		// With return value chaining, this would support creating the ip2 in Addr.Less(ip2 Addr) in netip.
		// If we restore this branch, set wrapperName = fmt.Sprintf("Fuzz_%s", f.Name())
		return errSilentSkip
	} else {
		n, err := namedType(recv)
		if err != nil {
			// output to stderr, but don't treat as fatal error.
			fmt.Fprintf(os.Stderr, "fzgen: warning: createWrapper: failed to determine receiver type: %v: %v\n", recv, err)
			return nil
		}
		// Check if we have a constructor that works.
		ctorMatch, err := constructorMatch(recv, constructor)
		if err != nil {
			return fmt.Errorf("genfuncsloop: error when looking for matching constructor: %v", err)
		}
		if ctorMatch.sig == nil {
			return errSilentSkip
		}

		recvNamedTypeLocalName := types.TypeString(n.Obj().Type(), localQualifier)
		wrapperName = fmt.Sprintf("Fuzz_%s_%s", recvNamedTypeLocalName, f.Name())
	}

	// Start building up our list of parameters we will use in input
	// parameters to the new wrapper func we are about to emit.
	var inputParams []*types.Var

	// Also add in the parameters for the function under test.
	// Note that we allow zero len Params because we only get this far
	// if we have a match on the receiver with the target object.
	for i := 0; i < wrappedSig.Params().Len(); i++ {
		v := wrappedSig.Params().At(i)
		inputParams = append(inputParams, v)
	}

	paramReprs := make([]paramRepr, len(inputParams))
	for i, v := range inputParams {
		typeStringWithSelector := types.TypeString(v.Type(), defaultQualifier)
		paramName := avoidCollision(v, i, localPkg, inputParams)
		paramReprs[i] = paramRepr{paramName: paramName, typ: typeStringWithSelector, v: v}
	}

	// Check if we have an interface or function pointer in our desired parameters,
	// which we can't fill with values during fuzzing.
	support, unsupportedParam := checkParamSupport(inputParams)
	if support == noSupport {
		// skip this wrapper.
		emit("// skipping %s because parameters include func, chan, or unsupported interface: %v\n\n", wrapperName, unsupportedParam)
		return errSilentSkip
	}

	// Start emitting the wrapper function, inside of a fzgen/fuzzer.Step. Will be similar to:
	//   Step{
	// 	   Name: "input int",
	// 	   Func: func(a int) int {
	//	          return a
	//     }
	//   },
	emit("\t{\n")
	emit("\t\tName: \"%s\",\n", wrapperName)
	emit("\t\tFunc: func(")

	switch support {
	case nativeSupport, fillRequired:
		// For independent wrappers, in some cases we need to emit fz.Fill to handle
		// creating rich args that are beyond what cmd/go can fuzz (including because
		// the standard go test infrastructure will be calling the wrappers we created).
		// In contrast, for the chain steps we are creating here, we emit the same
		// code for both nativeSupport and fillRequired, and handle the difference at run time.
		// This is because for chain steps, we never emit fz.Fill calls because at run time
		// we are the ones to call the function literal, and hence we create those rich args
		// at run time, and hence here we just create function literals with the arguments
		// we want.
		//
		// The result for this line will end up similar to:
		//    Func: func(s string, i *int) {
		// Iterate over the our input parameters and emit.
		for i, p := range paramReprs {
			// want: foo string, bar int
			if i > 0 {
				// need a comma if something has already been emitted
				emit(", ")
			}
			emit("%s %s", p.paramName, p.typ)
		}
		emit(") ")

		// TODO: centralize error check logic
		results := wrappedSig.Results()
		if results.Len() > 0 && !(results.Len() == 1 && results.At(0).Type().String() == "error") {
			emit("(") // goimports should clean up paren if it is not needed
			for i := 0; i < results.Len(); i++ {
				if i > 0 {
					emit(", ")
				}
				returnTypeStringWithSelector := types.TypeString(results.At(i).Type(), defaultQualifier)
				emit(returnTypeStringWithSelector)
			}
			emit(")")
		}
		emit(" {\n")

		// For independent wrappers, we do emitNilChecks for parameters to avoid boring crashes,
		// but chained wrappers we always call new if we find a pointer at run time.
		// TODO: consider uintptr, unsafe.Pointer, ...
	default:
		panic(fmt.Sprintf("unexpected result from checkParamSupport: %v", support))
	}

	// Emit the call to the wrapped function.
	// collisionOffset is 0 because we do not have a constructor within this function
	// literal we are creating and hence we don't need to worry about calculating
	// a collisionOffset.
	// Include a 'return' if we have a non-error return value for our wrapped func.
	results := wrappedSig.Results()
	if results.Len() > 0 && !(results.Len() == 1 && results.At(0).Type().String() == "error") {
		emit("\treturn ")
	}
	emitWrappedFunc(emit, f, wrappedSig, "target", 0, qualifyAll, inputParams, localPkg)

	// close out the func as well as the Step struct
	emit("\t\t},\n")
	emit("\t},\n")
	return nil
}

// implementsEncodingMarshaler reports if f implements encoding.BinaryMarshaler or encoding.TextMarshaler.
// TODO: this is a bit quick. replace with table driven check that handles other common roundrip interfaces & patterns.
func implementsEncodingMarshaler(f *types.Func, desiredName string) (bool, error) {
	sig, ok := f.Type().(*types.Signature)
	if !ok {
		return false, fmt.Errorf("func %s is not *types.Signature (%+v)", f.Name(), f)
	}

	if f.Name() != desiredName {
		return false, nil
	}

	// check params
	params := sig.Params()
	if params.Len() != 0 {
		return false, nil
	}

	// check return values
	ctorResults := sig.Results()
	if ctorResults.Len() != 2 {
		return false, nil
	}

	// check if first return type is []byte.
	firstResult := ctorResults.At(0)
	if firstResult.Type().String() != "[]byte" && firstResult.Type().String() != "[]uint8" {
		return false, nil
	}

	// check if second return type is error type.
	secondResult := ctorResults.At(1)
	_, ok = secondResult.Type().Underlying().(*types.Interface)
	if !ok || secondResult.Type().String() != "error" {
		return false, nil
	}

	return true, nil
}

// implementsEncodingUnmarshaler reports if f implements encoding.BinaryUnmarshaler or encoding.TextUnmarshaler.
// TODO: this is a bit quick. replace with table driven check that handles other common roundrip interfaces & patterns.
func implementsEncodingUnmarshaler(f *types.Func, desiredName string) (bool, error) {
	sig, ok := f.Type().(*types.Signature)
	if !ok {
		return false, fmt.Errorf("func %s is not *types.Signature (%+v)", f.Name(), f)
	}

	if f.Name() != desiredName {
		return false, nil
	}

	// check params
	params := sig.Params()
	if params.Len() != 1 {
		return false, nil
	}

	// check if only param is []byte.
	param := params.At(0)
	if param.Type().String() != "[]byte" && param.Type().String() != "[]uint8" {
		return false, nil
	}

	// check return values
	ctorResults := sig.Results()
	if ctorResults.Len() != 1 {
		return false, nil
	}

	// check if only return type is error type.
	secondResult := ctorResults.At(0)
	_, ok = secondResult.Type().Underlying().(*types.Interface)
	if !ok || secondResult.Type().String() != "error" {
		return false, nil
	}

	return true, nil
}

// TODO: make template, and make table driven to handle additional common patterns.
var encodingTextMarshalerRoundtripTmpl string = `
		// Check MarshalText.
		result1, err := target.MarshalText()
		if err != nil {
				// Some targets should never return an error here for an object created by a constructor.
				// If that is the case for your target, you can change this to a panic(err) or t.Fatal.
				return
		}

		// Check UnmarshalText.
		var tmp1 %s
		err = tmp1.UnmarshalText(result1)
		if err != nil {
			panic(fmt.Sprintf("UnmarshalText failed after successful MarshalText. original: %%v marshalled: %%q error: %%v", target, result1, err))
		}
		if !reflect.DeepEqual(target, tmp1) {
			panic(fmt.Sprintf("MarshalText/UnmarshalText roundtrip equality failed. original: %%v  marshalled: %%q unmarshalled: %%v", target, result1, tmp1))
		}
`

var encodingBinaryMarshalerRoundtripTmpl string = `
		// Check MarshalBinary.
		result2, err := target.MarshalBinary()
		if err != nil {
				// Some targets should never return an error here for an object created by a constructor.
				// If that is the case for your target, you can change this to a panic(err) or t.Fatal.
				return
		}

		// Check UnmarshalBinary.
		var tmp2 %s
		err = tmp2.UnmarshalBinary(result2)
		if err != nil {
			panic(fmt.Sprintf("UnmarshalBinary failed after successful MarshalBinary. original: %%v %%#v marshalled: %%q error: %%v", target, target, result2, err))
		}
		if !reflect.DeepEqual(target, tmp2) {
			panic(fmt.Sprintf("MarshalBinary/UnmarshalBinary roundtrip equality failed. original: %%v %%#v marshalled: %%q unmarshalled: %%v %%#v",
				  target, target, result2, tmp2, tmp2))
		}
`
