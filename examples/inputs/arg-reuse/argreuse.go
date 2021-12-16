// Package argexample shows an example that would take longer to
// to panic simply using dvyukov/go-fuzz or 'go test -fuzz=.',
// but which should panic in 20-30 sec or so via fz.Chain
// when fz.Chain is properly reusing input arg values from a step
// as candidate input values to another step (currently
// just a few seconds with GODEBUG=fuzzseed=1, vs. 2-3 minutes for
// cmd/go fuzzing without arg reuse).
//
// To panic, this example has three requirements:
//    1. Step1 must be called.
//    2. Step2 must be subsequently called.
//    3. The two args passed to Step2 must match the first arg of Step1.
//
// fz.Chain usually solves this by wiring the one of the args to Step1 to the inputs to Step2.
//
// The intent is that this example is run sequentially (that is, not with concurrent steps).
//
// (go-fuzz and cmd/go fuzzing can solve this many ways, including by copying
// bytes, or picking same interesting values in the right spots, etc.).
package argexample

type PanicOnArgReuse struct {
	rememberedInt int64
	passedStep1   bool
}

func New(i int) *PanicOnArgReuse {
	return &PanicOnArgReuse{}
}

func (p *PanicOnArgReuse) Step1(a, b int64) {
	// zero value is too easy, as are repeating values.
	if a != b && a != 0 && b != 0 {
		p.rememberedInt = a
		p.passedStep1 = true
	}
}

func (p *PanicOnArgReuse) Step2(a, b int64) {
	// TODO: fuzzer should reuse args beyond first arg, and then change this to b == p.rememberedB
	if a == p.rememberedInt && b == p.rememberedInt && p.passedStep1 {
		panic("bingo - found our desired panic")
	}
}
