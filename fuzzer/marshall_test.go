package fuzzer

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	raceexample "github.com/thepudds/fzgen/examples/inputs/race"
	"github.com/thepudds/fzgen/fuzzer/internal/plan"
)

func TestUnmarshalPlan(t *testing.T) {
	tests := []struct {
		name              string
		data              []byte
		wantConsumedBytes int
		wantPlan          plan.Plan
	}{
		{
			name: "read exactly",
			// this attempts to read 2 calls
			data:              []byte{201, 0x1, 0x2, 0x6, 0x1, 0x7, 0x0, 0x2, 0x8},
			wantConsumedBytes: 9,
			wantPlan: plan.Plan{
				GoroutineOrdering: 0,
				Calls: []plan.Call{
					{
						StepIndex: 1, // Store
						ArgSource: []plan.ArgSource{
							{
								SourceType: 2, // corresponds to new arg
								ArgIndex:   6,
							},
							{
								SourceType: 1, // corresponds to re-use return
								ArgIndex:   7,
							},
						},
					},
					{
						StepIndex: 0, // Load
						ArgSource: []plan.ArgSource{{
							SourceType: 2, // corresponds to new arg
							ArgIndex:   8,
						}},
					},
				},
			},
		},
		{
			name: "read with 1 extra byte left over",
			// this attempts to read 2 calls, with a final byte left over
			data:              []byte{201, 0x1, 0x2, 0x6, 0x1, 0x7, 0x0, 0x2, 0x8, 0x1},
			wantConsumedBytes: 9,
			wantPlan: plan.Plan{
				GoroutineOrdering: 0,
				Calls: []plan.Call{
					{
						StepIndex: 1, // Store
						ArgSource: []plan.ArgSource{
							{
								SourceType: 2, // corresponds to new arg
								ArgIndex:   6,
							},
							{
								SourceType: 1, // corresponds to re-use return
								ArgIndex:   7,
							},
						},
					},
					{
						StepIndex: 0, // Load
						ArgSource: []plan.ArgSource{{
							SourceType: 2, // corresponds to new arg
							ArgIndex:   8,
						}},
					},
				},
			},
		},
		{
			name: "short read with one complete call found",
			// this attempts to read 2 calls, but only finds one complete call
			data:              []byte{201, 0x1, 0x2, 0x6, 0x1, 0x7, 0x0, 0x2},
			wantConsumedBytes: 8,
			wantPlan: plan.Plan{
				GoroutineOrdering: 0,
				Calls: []plan.Call{
					{
						StepIndex: 1, // Store
						ArgSource: []plan.ArgSource{
							{
								SourceType: 2, // corresponds to new arg
								ArgIndex:   6,
							},
							{
								SourceType: 1, // corresponds to re-use return
								ArgIndex:   7,
							},
						},
					},
				},
			},
		},
		{
			name: "short read with no complete call found",
			// this attempts to read 2 calls, but does not find any complete call
			data:              []byte{201, 0x1, 0x2},
			wantConsumedBytes: 3,
			wantPlan: plan.Plan{
				GoroutineOrdering: 0,
				Calls:             nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			buf := bytes.NewBuffer(tt.data)
			gotPlan := unmarshalPlan(buf, steps)
			if diff := cmp.Diff(tt.wantPlan, gotPlan); diff != "" {
				t.Errorf("unmarshalPlan() mismatch (-want +got):\n%s", diff)
			}

			gotConsumedBytes := len(tt.data) - buf.Len()
			if tt.wantConsumedBytes != gotConsumedBytes {
				t.Errorf("unmarshalPlan() expected consumed bytes: %v, got: %v", tt.wantConsumedBytes, gotConsumedBytes)
			}
		})
	}
}
