package fuzzer

import (
	"encoding/binary"
	"io"

	"github.com/thepudds/fzgen/fuzzer/internal/plan"
)

// unmarshalPlan consumes bytes to construct a Plan describing
// which calls we will fuzz, in what order, and how their
// arguments will be obtained (e.g., new value, re-used arg, re-used return val).
// It attempts to return plan.Calls that are fully covered by the input bytes
// in an effort to be friendlier to corpus evolution.
// If a call is included in the returned Plan, its argument sources
// are fully described by the bytes, though if an argument source in a plan.Call
// is a new argument, there might not be enough subsequent bytes to fully fill the argument
// value, which currently means it might be filled with the zero value for a basic type
// or have zero values for some elements if it is a composite type.
// This is hopefully reasonably friendly to the underlying fuzzing engine,
// including the coverage-guided evolution and tail trim minimization, which is currently
// the first minimization technique for both cmd/go and dvyukov/go-fuzz.
//
// It is the caller's responsibility to track how many bytes are consumed.
// E.g., caller could do:
//   buf := bytes.NewReader(data)
//   pl := unmarshalPlan(buf, ...)
//   used := len(data) - buf.Len()
func unmarshalPlan(r io.Reader, steps []Step) plan.Plan {
	pl := plan.Plan{}

	var callCountByte uint8
	var callCount int
	err := binary.Read(r, binary.LittleEndian, &callCountByte)
	if err != nil {
		return pl
	}
	// Favor a few calls over, say, 2 or 8.
	switch {
	case callCountByte < 64:
		callCount = 3
	case callCountByte < 128:
		callCount = 4
	case callCountByte < 192:
		callCount = 5
	default:
		// TODO: Current max calls in our plan is 10. Probably make this configurable.
		// Note that a loop means we might execute more than 10 calls total (e.g., loop of 256 with
		// callCount of 10 would mean 2560 total calls executed).
		callCount = int(callCountByte%10) + 1
	}

	// skip GoroutineOrdering
	for i := 0; i < callCount; i++ {
		// Try to read a new Call.
		// If we can't fully populate call.StepIndex and the ArgSource slice with right count of args,
		// we will not use this call (which is probably friendlier to mutator/evoluation than completing a partial
		// using zeros or similar).
		call := plan.Call{}

		// Read call.StepIndex.
		err := binary.Read(r, binary.LittleEndian, &call.StepIndex)
		// Recall, for binary.Read:
		//   err is io.EOF only if no bytes were read.
		//   If an io.EOF happens after reading some but not all the bytes, binary.Read returns io.ErrUnexpectedEOF.
		if err != nil {
			// We don't use a partially read Call.
			break
		}

		// Based on the StepIndex we just read, compute the actual index into the user's Step list.
		s := int(call.StepIndex) % len(steps)
		fv := mustFunc(steps[s].Func)
		ft := fv.Type()

		argSources := make([]plan.ArgSource, ft.NumIn())
		err = binary.Read(r, binary.LittleEndian, &argSources)
		if err != nil {
			// We don't use a partially read Call, including if we haven't filled in
			// all of the needed ArgSource for this step's signature.
			break
		}
		// Success, add to the plan and continue.
		// If we exactly finished the bytes, we break out of the loop next iteration with io.EOF.
		call.ArgSource = append(call.ArgSource, argSources...)
		pl.Calls = append(pl.Calls, call)
	}
	return pl
}
