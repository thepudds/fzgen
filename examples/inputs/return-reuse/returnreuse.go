// Package returnexample shows an example that would be quite
// challenging to panic simply using dvyukov/go-fuzz or 'go test -fuzz=.',
// but which should panic almost immediately via fz.Chain
// when fz.Chain is properly wiring the return values from a step
// as candidate input values to another step.
//
// To panic, this example has three requirements:
//    1. Step1 must be called, where Step1 returns the sha256 of its input uint64.
//    2. Step2 must be subsequently called.
//    3. The sha256 of the uint64 passed to the most recent Step1 must equal the [32]byte passed to Step2.
//
// fz.Chain solves this by wiring the output of Step1 to the input to Step2.
//
// The intent is that this example is run sequentially (that is, not with concurrent steps).
//
// (go-fuzz's sonar won't look at a [32]byte sha256, and
// neither will the current value comparison instrumentation in 'go test -fuzz=.',
// and there are no magic literals to automatically learn for a dictionary).
package returnexample

import (
	"crypto/sha256"
	"encoding/binary"
)

type PanicOnReturnReuse struct {
	rememberedSha [32]byte
	calledStep1   bool
}

func New(i int) *PanicOnReturnReuse {
	return &PanicOnReturnReuse{}
}

func (p *PanicOnReturnReuse) Step1(input uint64) [32]byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, input)
	p.rememberedSha = sha256.Sum256(b)
	p.calledStep1 = true
	return p.rememberedSha
}

func (p *PanicOnReturnReuse) Step2(inputSha [32]byte) {
	if inputSha == p.rememberedSha && p.calledStep1 {
		panic("bingo - found our desired panic")
	}
}
