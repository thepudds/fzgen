package plan

type Plan struct {
	GoroutineOrdering byte   // TODO: currently unused. delete or restore. was used as seed value.
	Calls             []Call // sequential list of steps to execute
}

// Call represents a function call we intend to make, based on the
// fuzzer.Step funcs were selected in our Plan.
type Call struct {
	// These will be filled in from the data []byte from the core fuzzing engine (go-fuzz or cmd/go)
	// via fz.Fill.
	StepIndex uint8       // which Step in steps does this represent, mod len(steps) (or if > len(steps ==> stop)
	ArgSource []ArgSource // list of how to create arguments for this Step. Zero len ==> all new args. If len is > args, ignore extra.
}

// ArgSource represents how to obtain values for one argument to an ExecStep.
// Values can come from:
//     reusing inputs to other ExecSteps
//     reusing outputs from other Exect steps
//     a new value
// When attempting to reuse an input or output to another ExecStep, if there is a mismatch on type,
// or if asked to use non-existent return values for source step,
// we first try flipping from new args to outputs or vice versa, then fallback to new value.
// In future, could consider increment through arg/output slots, and increment through ExecSteps prior to ultimately falling back to new value.
// In other words, the ArgSource would indicate where to start our search for a matching type, and
// then could exaustively & deterministcally look for match.
// ASCII '0' is dec 48. 48 mod 3 = 0. Given go-fuzz and probably cmd/go like 0x0 as well as ASCII '0', we pick reusing source for SourceType % 3==0.
type ArgSource struct {
	SourceType uint8 // mod 3: 0 means reuse arg from source ExecStep, 1 is reuse output from source ExecStep, 2 is new arg.
	ArgIndex   uint8 // which source element, such as all prior input args of a given type, mod len(source).
}
