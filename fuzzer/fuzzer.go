// Package fuzzer supports fuzzing rich signatures via the Fill method, as well as
// the ability to automatically chain Steps together under
// the control of the fuzzer using the Chain method.
//
// Package fuzzer can be used completely independently from the fzgen command
// by manually constructing fuzzing functions, or the fzgen command can
// be used to automatically create wrappers that use package fuzzer.
//
// See the project README for additional information:
//     https://github.com/thepudds/fzgen
package fuzzer

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/sanity-io/litter"
	"github.com/thepudds/fzgen/fuzzer/internal/plan"
	"github.com/thepudds/fzgen/fuzzer/internal/randparam"
)

// SupportedInterfaces enumerates interfaces that can be filled by Fill(&obj).
var SupportedInterfaces = randparam.SupportedInterfaces

// Step describes an operation to step the system forward.
// Func can take any number of arguments and return any number of values.
// The Name string conventionally should be an acceptable func identifier.
// See Chain for more details on usage.
type Step struct {
	Name string
	Func interface{}
}

// Fuzzer is a utility object that can fill in many types
// such as io.Reader, structs, maps, and so on, as well as supports chaining over a set of
// functions in sequence, including connecting output to inputs
// and re-using inputs (e.g., to help exercise APIs like a Store followed
// by a Load).
// Conventially called 'fz'.
type Fuzzer struct {
	data            []byte
	randparamFuzzer *randparam.Fuzzer
	execState       *execState

	chainOpts chainOpts
}

type FuzzerOpt func(*Fuzzer) error

// NewFuzzer returns a Fuzzer, which relies on the input data []byte
// to control its subsequent operations.
// In the future, NewFuzzer may take options, though currently does not.
func NewFuzzer(data []byte, options ...FuzzerOpt) (fz *Fuzzer) {
	fill := randparam.NewFuzzer(data)
	state := &execState{
		reusableInputs: make(map[reflect.Type][]*reflect.Value),
		outputSlots:    make(map[reflect.Type][]*outputSlot),
		// TODO: not needed?
		// reusableOutputs: make(map[reflect.Type][]reflect.Value),
	}
	return &Fuzzer{
		data:            data,
		randparamFuzzer: fill,
		execState:       state,
	}
}

// Fill fills in most simple types, maps, slices, arrays, and recursively fills any public members of x.
// It supports about 20 or so common interfaces, such as io.Reader, io.Writer, or io.ReadWriter.
// See SupportedInterfaces for current list of supported interfaces.
// Callers pass in a pointer to the object to fill, such as:
//    var i int
//    Fill(&i)
//    var r io.Reader
//    Fill(&r)
//    var s1, s2 string
//    Fill(&s1, &s2)
// Fill ignores channels, func pointers, complex64, complex128, and uintptr,
// For number, string, and []byte types, it tries to populate the obj value with literals found in the initial input []byte.
//
// In order to maximize deterministic behavior, help guide the fuzzing engine, and allow for generation of reproducers,
// Fill must not be called from within the Steps used with Chain. If you need additional values within a Step, add
// them as parameters to the Step, and Chain will fill those parameters.
func (fz *Fuzzer) Fill(x ...interface{}) {
	// TODO: probably panic if called from within Chain.
	for _, arg := range x {
		before := fz.randparamFuzzer.Remaining()

		fz.randparamFuzzer.Fill(arg)

		if debugPrintPlan {
			fmt.Printf("fzgen: filled object of type \"%T\" using %d bytes. %d bytes remaining.\n",
				arg, before-fz.randparamFuzzer.Remaining(), fz.randparamFuzzer.Remaining())
		}
	}
}

type execState struct {
	// reusableInputs is a map from type to list of all new args of that type from all steps,
	// ordered by the sequence of calls defined the Plan and the order within the args of a
	// given Call from the plan.
	// Each entry in the map is a slice of the filled-in reflect.Values for that reflect.Type
	// for each argument in the plan that is defined to be a new value (and not a reused input or output).
	// For example, if the plan is effectively:
	//    call1(a, b string)
	//    call2(c int, d string)
	// then the map entry for key of reflect.Type string would be {a, b, d} as long as a, b, and d are defined
	// by the plan to be new values. On the other hand, if the plan defines d to reuse a's input value,
	// then the map entry for key of reflect.Type string would be {a, b}, without d.
	reusableInputs map[reflect.Type][]*reflect.Value

	// outputSlots is map from type to return value slots, covering the complete set of return types in all calls in the plan,
	// and ordered by the sequence of calls defined the Plan and the order of the return values of a
	// given Call from the plan.
	// It is used as an intermediate step prior to actually invoking any calls
	// to determine which if any return values should be saved when it is time to invoke a specific call.
	// TODO: we probably could collapse outputSlots and reusableOutputs.
	outputSlots map[reflect.Type][]*outputSlot

	// reusableOutputs is a map of from type to list of all return values that will be used as later inputs.
	// It is similar in spirit to reusableInputs, but whereas reusableInputs contains all new input values,
	// reusableOutputs only contains returns values that are planned to be reused by a subsequent call.
	// For example, if the plan is effectively:
	//    call1() int
	//    call2(a int)
	// and the plan defines that call2 will attempt to reuse an int return value as its input arg,
	// then the map entry for key of reflect.Type int would be effectively be {{call1RetVal0}},
	// where call2 will use the zeroth return value from call1 as the input to call2.
	// After we invoke call1, we fill in the reflect.Value in the right slot of the slice.
	// When we later invoke call2, we read that value.
	// Note that we set up the slice (with invalid reflect.Values) before any concurrent goroutines run,
	// and then take care to read the reflect.Value (e.g., to invoke call2) only after it has been
	// filled in (e.g., after the invocation of call1).
	// TODO: not needed?
	// reusableOutputs map[reflect.Type][]reflect.Value
}

// execCall represents a function call we intend to make, based on which
// fuzzer.Step func was selected in our Plan.
type execCall struct {
	planCall plan.Call // raw plan.Call filled in by fz.Fill

	name        string
	index       int           // zero-based index of this call. currently only used for emitting variable name for repro.
	fv          reflect.Value // func we will call.
	args        []argument    // arguments for this call, some of which might initially be placeholder invalid reflect.Value.
	outputSlots []*outputSlot // pointers to the output slots for this call's return values.
}

type argument struct {
	useReturnVal bool           // indicates if this argument will come from another call's return value.
	typ          reflect.Type   // type of input argument.
	val          *reflect.Value // argument value to use.
	slot         *outputSlot    // slot of the return value.
}

type outputSlot struct {
	// Indicates if this return value will be used by a subsequent call. If false,
	// we don't store the value after the corresponding call completes.
	needed bool
	// Type of return value.
	typ reflect.Type
	// Return value to use. Initially set to invalid reflect.Value{}, which is filled
	// in after the corresponding call completes.
	val reflect.Value
	// Channel to broadcast via close(ch) that the return value val is ready to be read.
	ch chan struct{}
	// zero-indexed call that the return value will come from.
	returnValCall int
	// zero-indexed arg from that call that the return value will come from.
	returnValArg int
}

type ChainOpt func(*Fuzzer) error

type chainOpts struct {
	parallel bool
}

// ChainParallel indicates the Fuzzer is allowed to run the
// defined set of Steps in parallel. The Fuzzer can choose to run
// all selected Steps in parallel, though most often prefers
// to run only a portion of Steps in parallel in a single
// Chain execution in order to increase deterministic behavior
// and help the underlying fuzzing engine evolve interesting inputs.
// Care is taken so that a given corpus will result in the same
// Steps executing with the same arguments regardless of
// whether or not ChainParallel is set.
//
// ChainParallel is most often useful with the race detector, such as
// 'go test -fuzz=. -race', though because the race detector
// can have 10x-20x performance impact, one approach is to
// run for a period of time with ChainParallel set but
// without the race detector to build up a larger corpus faster,
// and then later run with the race detector enabled.
func ChainParallel(fz *Fuzzer) error {
	fz.chainOpts.parallel = true
	return nil
}

// Chain invokes a set of Steps, looking for problematic sequences and input arguments.
// The Fuzzer chooses which Steps to calls and how often to call them,
// then creates any needed arguments, and calls the Steps in a sequence selected by the fuzzer.
// The only current option is ChainOptParallel.
// If the last return value of a Step is of type error and a non-nil value is returned,
// this indicates a sequence of Steps should stop execution,
// The only current option is ChainOptParallel.
func (fz *Fuzzer) Chain(steps []Step, options ...ChainOpt) {
	// Start by filling in our plan, which will let us know the sequence of steps along
	// with sources for input args (which might be re-using input args,
	// or using return values, or new values from fz.Fill).
	pl := plan.Plan{}
	before := fz.randparamFuzzer.Remaining()
	switch debugPlanVersion {
	case 2:
		// Current approach.
		// Get any remaining bytes from randparamFuzzer.
		data := fz.randparamFuzzer.Data()
		buf := bytes.NewReader(data)

		// Convert those bytes into a Plan.
		pl = unmarshalPlan(buf, steps)

		// Drain from randparamFuzzer any bytes we used building the Plan.
		used := len(data) - buf.Len()
		fz.randparamFuzzer.Drain(used)
	default:
		panic("unexpected debugPlanVersion")
	}

	if debugPrintPlan {
		emitPlan(pl)
		fmt.Printf("fzgen: filled Plan using %d bytes. %d bytes remaining.\n",
			before-fz.randparamFuzzer.Remaining(), fz.randparamFuzzer.Remaining())
	}

	// Using functional options.
	// (Side note: Rob Pike's blog introducing functional options is a great read:
	//     https://commandcenter.blogspot.com/2014/01/self-referential-functions-and-design.html)
	for _, opt := range options {
		// For a minor bit of improved call location backwards compat, skip any nil opts in case we have older generated code with a nil as
		// second argument.
		if opt == nil {
			continue
		}
		err := opt(fz)
		if err != nil {
			// TODO: currently we have no errors. panic is probably the right way to communicate from inside a fuzz func.
			panic(err)
		}
	}

	fz.chain(steps, pl)
}

func (fz *Fuzzer) chain(steps []Step, pl plan.Plan) {
	parallelAllowed := fz.chainOpts.parallel

	// First, determine if we will spin and loop for any parallel calls.
	allowSpin, loopCount := fz.calcParallelControl()

	// Second, create our list of execCalls based on the list of plan.Calls.
	// We do not yet fully populate the arguments for an execCall,
	// which we will do on a subsequent pass.
	var execCalls []execCall
	for i := range pl.Calls {
		// Based on the plan, compute index into the user's Step list.
		s := int(pl.Calls[i].StepIndex) % len(steps)

		ec := execCall{
			planCall: pl.Calls[i],
			name:     steps[s].Name,
			index:    i,
			fv:       mustFunc(steps[s].Func),
			args:     []argument{}, // empty to start, we will fill in below.
		}

		execCalls = append(execCalls, ec)
	}

	// Third, create arguments as needed for each execCall,
	// or record that we will obtain an argument from the
	// return value of an earlier execCall.
	for i := range execCalls {
		allowReturnValReuse := loopCount == 1
		// Build arguments for this call, and also get its reflect.Value function.
		// This can update the execCall to track outputSlots.
		args := fz.prepareStep(&execCalls[i], allowReturnValReuse, fz.Fill)

		// Track what we need to execute this call later.
		execCalls[i].args = args
	}

	// TODO: consider reintroducing shuffle of plan or execCalls, though might have less benefit after interweaving filling args
	// with filling the plan, which then gives the fuzzing engine a better chance of reordering.
	// (We've tried a few different variations of rand-based shuffling of plan or execCalls, and not clear how helpful.
	// If we shuffle, care must be taken around re-using input args (for example, could shuffle after that),
	// as well as around re-using return values (for example, could shuffle before that is set up to avoid shuffling
	// our way into a deadlock on the arg ready channel).

	sequential := true
	var startParallelIndex, stopParallelIndex int // inclusive range
	var parallelPlan byte
	// This is purposefully the last byte drawn (after the Plan and after our args have all been filled),
	// including so that tail-trim minimization will elimanate this from our input data []byte
	// If the byte was uniformaly random:
	//   1/8 of time - serial
	//   3/4 of time - parallel pair
	//   1/8 of time - parallel for up to N from end
	// However, if the byte in missing (e.g., tail trim minimization) it will be drawn
	// as the zero value, which purposefully means serial here,
	// and which means serial will be favored if the observed coverage or crash still happens serially.
	// Also, we try to take advantage of ASCII '0' minimization behavior of cmd/go
	// to mean serial, and then as cmd/go minimization steps to ASCII '1', '2', '3', ...,
	// we interpret those to mean pair parallel, stepping from the end.
	fz.Fill(&parallelPlan)
	if parallelAllowed && len(execCalls) > 1 {
		switch {
		case parallelPlan == '0' || parallelPlan < 32:
			sequential = true
		case parallelPlan < 224:
			startParallelIndex, stopParallelIndex = calcParallelPair(parallelPlan, len(execCalls))
			sequential = false
		default:
			startParallelIndex, stopParallelIndex = calcParallelN(parallelPlan, len(execCalls))
			sequential = false
		}
	}

	if sequential {
		// This only matters for debug output, but might as well make it clear.
		allowSpin, loopCount = false, 1
	}

	if debugPrintPlan {
		fmt.Printf("fzgen: parallelPlan byte: %v startParallelIndex: %d stopParallelIndex: %d sequential: %v\n",
			parallelPlan, startParallelIndex, stopParallelIndex, sequential)
	}
	if debugPrintRepro {
		if sequential {
			fmt.Printf("PLANNED STEPS: (sequential: %v)\n\n", sequential)
		} else {
			fmt.Printf("PLANNED STEPS: (sequential: %v, loop count: %d, spin: %v)\n\n", sequential, loopCount, allowSpin)
		}
		emitBasicRepro(execCalls, sequential, startParallelIndex, stopParallelIndex)
	}

	// Invoke our chained calls!
	if sequential {
		for _, ec := range execCalls {
			fz.callStep(ec)
		}
	} else {
		var wg sync.WaitGroup
		for i := range execCalls {
			// Spin between parallel calls.
			if allowSpin && i > startParallelIndex && i <= stopParallelIndex {
				runtime.Gosched()
				spin()
			}

			if i >= startParallelIndex && i <= stopParallelIndex {
				// This is a call we will run in parallel.
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					for j := 0; j < loopCount; j++ {
						fz.callStep(execCalls[i])
					}
				}(i)

				if i == stopParallelIndex {
					// Return to sequential execution, waiting on our in-flight goroutines
					// we just started above.
					wg.Wait()
				}
			} else {
				// Everything outside of start/StopParallelIndex runs sequentially.
				fz.callStep(execCalls[i])
			}
		}
	}
}

// calcParallelControl draws and interprets bytes to control our spinning and looping.
func (fz *Fuzzer) calcParallelControl() (allowSpin bool, loopCount int) {
	// TODO: probably move drawing the bytes to marshal.go.
	// TODO: orderPlan is not currently implemented, but we reserve a byte.
	// (Previously, we had a couple different flavors of randomized goroutine ordering
	// via a seed byte, but that is disabled).
	var spinPlan, loopPlan, orderPlan byte
	fz.Fill(&spinPlan, &loopPlan, &orderPlan)

	// We prefer to spin (mostly to aid with reproducibility), including if '0' or 0x0 appear during minimization.
	// (And yes, '0' is less than 192, but being explicit here as reminder when the numbers get juggled).
	allowSpin = spinPlan == '0' || loopPlan < 192

	// We prefer to not to loop much (mostly for perf & mem usage), including if '0' or 0x0 appear during minimization.
	switch {
	case loopPlan == '0' || loopPlan < 128:
		loopCount = 1
	case loopPlan < 224:
		loopCount = 4
	case loopPlan < 250:
		loopCount = 16
	case loopPlan < 254:
		loopCount = 64
	default:
		loopCount = 256
	}

	if loopCount >= 16 {
		// Disable spin for larger loop counts.
		// This is partly to help with performance, and more debatable,
		// the types of concurrency bugs that benefit from a large loop count
		// might tend to benefit from starting parallel loops at the same time without
		// an artificial delay between starts.
		allowSpin = false
	}
	return allowSpin, loopCount
}

// calcParallelPair interprets the bytes from our Plan to indicate when we
// should start and stop parallel execution for a pair of calls.
func calcParallelPair(parallelPlan byte, execCallLen int) (startParallelIndex, stopParallelIndex int) {
	// startParallelIndex is index of the first exeCall of the pair to run in parallel.
	// In general, we want to favor (1) sequential and (2) putting the parallelism as far towards the
	// end of a call sequence as we can, including so that new coverage which might have
	// been first *observed* with a logical race (e.g., two racing stores that are not a data race)
	// is minimized down to sequential behavior when possible.
	// We offset from '0' to take advantage of current cmd/go minimizing behavior
	// of trying '0', then '1', then '2', ... for each byte when minimizing:
	//    '0' is handled above, which we want to mean serial
	//    '1' we handle here, which we want to mean the last and second-to-last are in parallel.
	//    '2' means second-to-last and third-to-last in parallel, and so on.
	// We subtract 1 from the right-side mod operand because the last execCall would be a no-op as startParallelIndex,
	// and hence there are only len(execCalls)-1 interesting values for startParallelIndex here.
	offset := int(parallelPlan-'1') % (execCallLen - 1)

	stopParallelIndex = execCallLen - 1 - offset
	startParallelIndex = stopParallelIndex - 1

	if startParallelIndex < 0 {
		panic("bug computing startParallelIndex")
	}
	if stopParallelIndex >= execCallLen {
		panic("bug computing stopParallelIndex")
	}
	return startParallelIndex, stopParallelIndex
}

// calcParallelN interprets the bytes from our Plan to indicate when we
// should start and stop parallel execution, which will be up to N calls in parallel from the end
// of the plan.
func calcParallelN(parallelPlan byte, execCallLen int) (startParallelIndex, stopParallelIndex int) {
	offset := int(parallelPlan) % (execCallLen - 1)

	startParallelIndex = execCallLen - 2 - offset
	stopParallelIndex = execCallLen - 1

	if startParallelIndex < 0 {
		panic("bug computing startParallelIndex")
	}
	if stopParallelIndex >= execCallLen {
		panic("bug computing stopParallelIndex")
	}
	return startParallelIndex, stopParallelIndex
}

func (fz *Fuzzer) callStep(ec execCall) []reflect.Value {
	// TODO: don't need all these args eventually

	for _, arg := range ec.args {
		if arg.useReturnVal {
			// Wait until the return value is ready to be read.
			<-arg.slot.ch
		}
	}

	// Prepare the reflect.Value arg list we will use to call the func.
	// This contains the input values we previously created.
	reflectArgs := []reflect.Value{}
	for i := range ec.args {
		v := *ec.args[i].val

		// For map, pointer, or slice, we disallow nil values to
		// be passed in as args by creating a new object here if nil. Note that we are not setting up
		// for example a map completely -- just making sure it is not nil.
		// In older versions, this arg nil check was emitted code someone could choose to delete.
		// We could return and skip this call (closer to older emitted logic), but
		// if we do that, we need to handle the outputslot broadcast channels for this call in case someone
		// is waiting or will be waiting on a return value from this call.
		// TODO: this is likely useful for Ptr, but less sure how useful this is for the other types here.
		// TODO: test this better. inputs/race/race.go tests this for Ptr, but this is slightly annoying to test
		// because fz.Fill avoids this. This occurs for example when the plan decides to reuse a call return
		// value and that function under test returns a nil. In that case, fz.Fill is not the one creating the value.
		// TODO: if we keep this, consider showing equivalent logic in the emitted repro logic, or maybe only when it matters.
		// TODO: consider skipping this instead, and emit the nil check logic in the repro.
		// TODO: make this configurable, including because people no longer have option of deleting the emitted nil checks.
		switch v.Kind() {
		case reflect.Ptr:
			if v.IsNil() {
				v = reflect.New(v.Type().Elem())
			}
		case reflect.Slice:
			if v.IsNil() {
				v = reflect.MakeSlice(v.Type(), 0, 0)
			}
		case reflect.Map:
			if v.IsNil() {
				v = reflect.MakeMapWithSize(v.Type(), 0)
			}
		case reflect.Interface:
			// TODO: consider checking Interface too. Or better to keep passing the code under test a nil?
		}
		reflectArgs = append(reflectArgs, v)
	}

	// Call the user's func.
	ret := ec.fv.Call(reflectArgs)

	if len(ret) != ec.fv.Type().NumOut() {
		panic("fzgen: mismatch on return value count")
	}
	if len(ret) != len(ec.outputSlots) {
		panic(fmt.Sprintf("fzgen: for execCall %v, mismatch on return value count vs. execCall.outputSlots count: %+v, %+v", ec.name, ret, ec.outputSlots))
	}

	// Check to see if any of these return results are needed by an subsequent call.
	if fz.execState != nil {
		for i := 0; i < ec.fv.Type().NumOut(); i++ {
			if ec.outputSlots[i].needed {
				// at least one subsequent call will use this return value.
				outV := ret[i]
				// sanity check types match
				outT := ec.fv.Type().Out(i)
				if outT != outV.Type() || outT != ec.outputSlots[i].typ {
					panic("fzgen: mismatch on return value types")
				}

				// store this return value in the right outputSlot for later use by a subsequent call.
				slot := ec.outputSlots[i]
				slot.val = outV

				// Broadcast that the slot.val is ready to be read.
				close(slot.ch)
			}
		}
	}

	// fmt.Println(ret)
	// fmt.Printf("ret: %T %v\n", ret[0], ret[0])
	return ret
}

func (fz *Fuzzer) prepareStep(ec *execCall, allowReturnValReuse bool, fillFunc func(...interface{})) []argument {
	// TODO: additional sanity checking on types?
	fv := ec.fv
	ft := fv.Type()

	// Build up a list of arguments that are filled in with fresh values, or via reusing prior values.
	args := []argument{}
	for i := 0; i < ft.NumIn(); i++ {
		// Create or find an input value
		var arg argument
		inT := ft.In(i)

		// Track if we will need to create a new arg via reflect.New (vs. reusing an input or output).
		createNew := true

		// Check if our plan indicates we should try to reuse an input or output.
		if fz.execState != nil && len(ec.planCall.ArgSource) > i {
			switch ec.planCall.ArgSource[i].SourceType % 3 {
			case 0:
				// Reuse an argument, if one can be found.
				inputs, ok := fz.execState.reusableInputs[inT]
				if ok && len(inputs) > 0 {
					// TODO: take index from plan eventually; for simple tests, fine to take first
					inV := inputs[0]
					// We want the Elem() for use below in Call, because
					// inV represents a pointer to the type we want (e.g. from reflect.New),
					// so we do the indirect via inV.Elem() to get our original type.
					inElem := inV.Elem()
					arg = argument{
						useReturnVal: false,
						typ:          inV.Type(),
						val:          &inElem,
					}
					createNew = false
				}
			case 1:
				if allowReturnValReuse {
					// Mark that we will use a return value from an earlier step, if one can be found.
					outputSlots, ok := fz.execState.outputSlots[inT]
					if ok && len(outputSlots) > 0 {
						// We found a return value.
						// TODO: BUG: Note that it could be from any step, including one which happens
						// after us.
						// TODO: take index from plan eventually; for simple tests, fine to take first
						outputSlot := outputSlots[0]
						outputSlot.needed = true
						arg = argument{
							useReturnVal: true,
							typ:          inT,
							val:          &outputSlot.val,
							slot:         outputSlot,
						}
						createNew = false
					}
				}
			}
		}

		if createNew {
			// Create a new instance.
			// Note: NOT doing anything special if inT represent a pointer type (including not calling Elem here)
			inV := reflect.New(inT)

			// inInf is an interface with a pointer as its value, for example, *string if inT.Kind() is string
			inIntf := inV.Interface()

			// Do the work of filling in this value
			fillFunc(inIntf)

			inElem := inV.Elem()
			arg = argument{
				useReturnVal: false,
				typ:          inV.Type(),
				val:          &inElem,
			}

			if fz.execState != nil {
				// This is a new arg, store for later.
				// (A reused input arg would have already beeen stored for later use).
				fz.execState.reusableInputs[arg.typ] = append(fz.execState.reusableInputs[arg.typ], arg.val)
				// TODO: simple pop for now
				if len(fz.execState.reusableInputs[arg.typ]) > 10 {
					fz.execState.reusableInputs[arg.typ] = fz.execState.reusableInputs[arg.typ][1:]
				}
			}
		}

		// Add this now useful value to our list of input args for this call.
		args = append(args, arg)
	}

	// Finally, add all of the return types for this call to our
	// set of all known return value types for all of our steps seen so far.
	// A later call might might use one of our return values as an input arg.
	if fz.execState != nil {
		for i := 0; i < fv.Type().NumOut(); i++ {
			outT := fv.Type().Out(i)
			slot := &outputSlot{
				needed:        false,
				typ:           outT,
				val:           reflect.Value{},
				ch:            make(chan struct{}),
				returnValCall: ec.index,
				returnValArg:  i,
			}
			fz.execState.outputSlots[outT] = append(fz.execState.outputSlots[outT], slot)
			// execCall.outputSlots is a slice containing slots for all return values for
			// the call, with slice elements ordered by the return value order of the call.
			ec.outputSlots = append(ec.outputSlots, slot)
			// panic(fmt.Sprintf("for type %v, appending to ec.outputSlots: %#v", outT, ec.outputSlots))
		}
	}

	return args
}

func mustFunc(obj interface{}) reflect.Value {
	fv := reflect.ValueOf(obj)
	if fv.Kind() != reflect.Func {
		panic(fmt.Sprintf("fzgen: Step.Func is not of type func. [kind: %v %%T: %T value: %v]", fv.Kind(), fv, fv))
	}
	return fv
}

var spinCount int

func spin() {
	// TODO: tune duration of spin down?
	// It's going to depend on funcs under test and HW and so on, but on one test with logical race that set up a data:
	//    1<<16 vs. no spin moved reproducibility from ~80% to ~95%
	//    1<<20 moved reproducibility to ~100%
	var i int
	for i < 1<<18 {
		i++
	}
	spinCount += i
}

var (
	debugPrintRepro  bool
	debugPrintPlan   bool
	debugPlanVersion int = 2
)

func emitPlan(pl plan.Plan) {
	litter.Config.Compact = false
	// TODO: Probably use litter.Options object
	fmt.Println("PLAN:")
	litter.Dump(pl)
	fmt.Println()
}

// emitBasicRepro is the start of a more complete standalone reproducer
// creation, which ultimately could be a standalone _test.go file
// that does not have any dependency on fzgen/fuzzer or testing.F.
//
// Example current output, showing:
//   - literals for new args filled in by fz.Fill
//   - literals for reused args
//   - temporary variables when an output val is wired to a later input arg.
//
// Output:
//
//     Fuzz_MySafeMap_Load(
//             [4]uint8{0,0,0,0},
//     )
//     __fzCall2Retval1 := Fuzz_MySafeMap_Load(
//             [4]uint8{0,0,0,0},
//     )
//     Fuzz_MySafeMap_Store(
//             [4]uint8{0,0,0,0},
//             __fzCall2Retval1,
//     )
func emitBasicRepro(calls []execCall, sequential bool, startParallelIndex int, stopParallelIndex int) {
	litter.Config.Compact = true
	// TODO: Probably use litter.Options object
	// TODO: litter.Config.HomePackage = "<local pkg>"

	for i, ec := range calls {
		parallelCall := false
		if !sequential && i >= startParallelIndex && i <= stopParallelIndex {
			parallelCall = true
		}

		// TODO: consider emitting spin?
		// if i > startParallelIndex && i <= stopParallelIndex {
		// 	fmt.Print("\n\tspin()\n")
		// }

		if parallelCall && i == startParallelIndex {
			if i != 0 {
				fmt.Println()
			}
			fmt.Print("\tvar wg sync.WaitGroup\n")
			fmt.Printf("\twg.Add(%d)\n\n", stopParallelIndex-startParallelIndex+1)
			fmt.Print("\t// Execute next steps in parallel.\n")
		}

		if parallelCall {
			fmt.Print("\tgo func() {\n")
			fmt.Print("\t\tdefer wg.Done()\n")
		}

		// start emititng the actual call invocation.
		if parallelCall {
			fmt.Print("\t\t")
		} else {
			fmt.Print("\t")
		}

		// check if we are reusing any of return values from this call.
		showReturn := false
		for _, slot := range ec.outputSlots {
			if slot.needed {
				showReturn = true
				break
			}
		}

		if showReturn {
			// emit assignement to return values, which can look like:
			//    __fzCall2Retval1, _, _ :=
			for i, slot := range ec.outputSlots {
				if i > 0 {
					fmt.Print(", ")
				}
				if !ec.outputSlots[i].needed {
					fmt.Print("_")
				} else {
					// one-based temp variable names for friendlier output.
					fmt.Printf("__fzCall%dRetval%d", slot.returnValCall+1, slot.returnValArg+1)
				}
			}
			fmt.Print(" := ")
		}

		// emit the args, which might just be literals, or
		// might include one or more temp variables for a return value.
		fmt.Printf("%s(\n", ec.name)
		for _, arg := range ec.args {
			if parallelCall {
				fmt.Print("\t")
			}
			if !arg.useReturnVal {
				fmt.Printf("\t\t%s,\n", litter.Sdump(arg.val.Interface()))
			} else {
				// one-based temp variable names for friendlier output.
				fmt.Printf("\t\t__fzCall%dRetval%d,\n", arg.slot.returnValCall+1, arg.slot.returnValArg+1)
			}
		}

		// close out the invocation of this call.
		if parallelCall {
			fmt.Print("\t\t)\n")
			fmt.Print("\t}()\n")
		} else {
			fmt.Print("\t)\n")
		}

		if parallelCall && i == stopParallelIndex {
			fmt.Print("\twg.Wait()\n")
			if i < len(calls)-1 {
				fmt.Printf("\n\t// Resume sequential execution.\n")
			}
		}
	}
	fmt.Println()
}

func init() {
	fzgenDebugParse()
}

func fzgenDebugParse() {
	debug := strings.Split(os.Getenv("FZDEBUG"), ",")
	for _, f := range debug {
		if strings.HasPrefix(f, "repro=") {
			debugReproVal, err := strconv.Atoi(strings.TrimPrefix(f, "repro="))
			if err != nil || debugReproVal > 1 {
				panic("unexpected repro value in FZDEBUG env var")
			}
			if debugReproVal == 1 {
				debugPrintRepro = true
			}
		}
		if strings.HasPrefix(f, "plan=") {
			debugPlanVal, err := strconv.Atoi(strings.TrimPrefix(f, "plan="))
			if err != nil || debugPlanVal > 1 {
				panic("unexpected repro value in FZDEBUG env var")
			}
			if debugPlanVal == 1 {
				debugPrintPlan = true
			}
		}
		if strings.HasPrefix(f, "planversion=") {
			debugPlanVersion, err := strconv.Atoi(strings.TrimPrefix(f, "planversion="))
			if err != nil || debugPlanVersion > 2 {
				panic("unexpected planversion value in FZDEBUG env var")
			}
		}
	}
}
