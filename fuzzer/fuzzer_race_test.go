//go:build race
// +build race

package fuzzer

import (
	"testing"

	raceexample "github.com/thepudds/fzgen/examples/inputs/race"
	"github.com/thepudds/fzgen/fuzzer/internal/plan"
)

// TODO: need to update this for new encoding -- all zero draw now ==> sequential, so no race

// These go test invocations are expected to crash with a race detector violation:
//     go test -run=SimpleRace/parallel -v -race
//     go test -run=SimpleRace -v -race
// This should not crash:
//     go test -run=SimpleRace/sequential -v -race
func TestFuzzerChainWithSimpleRace(t *testing.T) {
	tests := []struct {
		name string
		opt  *ChainOptions
		pl   plan.Plan
	}{
		{
			name: "sequential increment shared int",
			opt:  &ChainOptions{Parallel: false},
			pl: plan.Plan{
				GoroutineOrdering: 0,
				Calls: []plan.Call{
					{
						StepIndex: 0, // will be first call above
						ArgSource: []plan.ArgSource{{
							SourceType: 2, // corresponds to new arg, which for this test will be zero value
							ArgIndex:   0,
						}},
					},
					{
						StepIndex: 1, // will be second call above
						ArgSource: []plan.ArgSource{{
							SourceType: 2, // corresponds to new arg, which for this test will be zero value
							ArgIndex:   0,
						}},
					},
				},
			},
		},
		{
			name: "parallel increment shared int",
			opt:  &ChainOptions{Parallel: true},
			pl: plan.Plan{
				GoroutineOrdering: 0,
				Calls: []plan.Call{
					{
						StepIndex: 0, // will be first call above
						ArgSource: []plan.ArgSource{{
							SourceType: 2, // corresponds to new arg, which for this test will be zero value
							ArgIndex:   0,
						}},
					},
					{
						StepIndex: 1, // will be second call above
						ArgSource: []plan.ArgSource{{
							SourceType: 2, // corresponds to new arg, which for this test will be zero value
							ArgIndex:   0,
						}},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We create an Fuzzer, but we don't rely on the data []byte in this test
			// because we force a Plan, so we use an empty data []byte here.
			fz := NewFuzzer([]byte{})

			var shared int

			steps := []Step{
				{
					Name: "step 1: increment a shared variable",
					Func: func(a int) { shared++ }, // DATA RACE if called in parallel
				},
				{
					Name: "step 2: increment a shared variable",
					Func: func(a int) { shared++ }, // DATA RACE if called in parallel
				},
			}

			// Success is being flagged (or not) by race detector.
			// See comments at top of this test func.
			fz.chain(steps, tt.opt, tt.pl)
		})
	}
}

// These are expected to crash when run with the race detector:
//     go test -run=ComplexRace/parallel -v -race
//     go test -run=ComplexRace -v -race
// This should not crash:
//     go test -run=ComplexRace/sequential -v -race
func TestFuzzerChainWithComplexRace(t *testing.T) {
	tests := []struct {
		name string
		opt  *ChainOptions
		pl   plan.Plan
	}{
		{
			name: "sequential increment shared int",
			opt:  &ChainOptions{Parallel: false},
			pl: plan.Plan{
				GoroutineOrdering: 0,
				Calls: []plan.Call{
					{
						StepIndex: 0, // will be first call above
						ArgSource: []plan.ArgSource{{
							SourceType: 2, // corresponds to new arg, which for this test will be zero value
							ArgIndex:   0,
						}},
					},
					{
						StepIndex: 1, // will be second call above
						ArgSource: []plan.ArgSource{{
							SourceType: 2, // corresponds to new arg, which for this test will be zero value
							ArgIndex:   0,
						}},
					},
				},
			},
		},
		{
			name: "parallel increment shared int",
			opt:  &ChainOptions{Parallel: true},
			pl: plan.Plan{
				GoroutineOrdering: 0,
				Calls: []plan.Call{
					{
						StepIndex: 0, // will be first call above
						ArgSource: []plan.ArgSource{{
							SourceType: 2, // corresponds to new arg, which for this test will be zero value
							ArgIndex:   0,
						}},
					},
					{
						StepIndex: 1, // will be second call above
						ArgSource: []plan.ArgSource{{
							SourceType: 2, // corresponds to new arg, which for this test will be zero value
							ArgIndex:   0,
						}},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We create an Fuzzer, but we don't rely on the data []byte in this test
			// because we force a Plan, so we use an empty data []byte here.
			fz := NewFuzzer([]byte{})

			// target and steps here taken from:
			//    fzgen -chain -pkg=github.com/thepudds/fzgen/examples/inputs/race
			target := raceexample.NewMySafeMap()

			steps := []Step{
				{
					Name: "Fuzz_MySafeMap_Load",
					Func: func(key [16]byte) *raceexample.Request {
						return target.Load(key)
					},
				},
				{
					Name: "Fuzz_MySafeMap_Store",
					Func: func(key [16]byte, req *raceexample.Request) {
						if req == nil {
							return
						}
						target.Store(key, req)
					},
				},
			}

			// Success is being flagged (or not) by race detector.
			// See comments at top of this test func.
			fz.chain(steps, tt.opt, tt.pl)
		})
	}
}
