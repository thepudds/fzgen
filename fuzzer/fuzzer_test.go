package fuzzer

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/thepudds/fzgen/fuzzer/internal/plan"
)

func TestCallStep(t *testing.T) {
	tests := []struct {
		step Step // use Step.Name for subtest name
		want interface{}
	}{
		{
			Step{
				Name: "input int",
				Func: func(a int) int { return a },
			},
			int(42),
		},
		{
			Step{
				Name: "input int pointer",
				Func: func(a *int) int { return *a },
			},
			int(42),
		},
		{
			Step{
				Name: "input io.Reader",
				Func: func(r io.Reader) []byte {
					b, err := ioutil.ReadAll(r)
					if err != nil {
						panic(err)
					}
					return b
				},
			},
			[]byte{42},
		},
	}
	for _, tt := range tests {
		t.Run(tt.step.Name, func(t *testing.T) {
			// We create an Fuzzer, but we don't rely on the data []byte in this test
			// because we use a fake fill function, so we use an empty data []byte here.
			fz := NewFuzzer([]byte{})

			// The zero value of plan.Call{} is not generally useful for real clients,
			// but it works for this test.
			ec := execCall{
				planCall: plan.Call{},
				name:     tt.step.Name,
				fv:       mustFunc(tt.step.Func),
				args:     []argument{}, // empty list to start, will be populated by prepareStep
			}

			allowReturnValReuse := true
			args := fz.prepareStep(&ec, allowReturnValReuse, fakeFill)
			ec.args = args

			ret := fz.callStep(ec)

			if len(ret) != 1 {
				t.Fatalf("callStep() = %v, len %v, test function expects single element returned", ret, len(ret))
			}
			v := ret[0]
			gotIntf := v.Interface()

			if diff := cmp.Diff(tt.want, gotIntf); diff != "" {
				t.Errorf("callStep() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFuzzerChain(t *testing.T) {
	tests := []struct {
		name      string
		wantBingo bool // do we expect to find a "bingo" panic
		pl        plan.Plan
	}{
		{
			name:      "all new args",
			wantBingo: false,
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
			name:      "reuse arg for step1 in step2",
			wantBingo: false,
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
							SourceType: 0, // corresponds to reusing an input arg
							ArgIndex:   0,
						}},
					},
				},
			},
		},
		// Setup a sequential plan by hand that is effectively:
		//     ret := step1(0)  // 0 because with an empty data []byte, any filled in value will be the type's zero value.
		//     step2(ret)       // reuse return value from step1 based on how we set up plan below.
		{
			name:      "reuse return value from step 1 in step 2",
			wantBingo: true,

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
							SourceType: 1, // corresponds to using a return value
							ArgIndex:   0,
						}},
					},
				},
			},
		},
	}

	steps := []Step{
		{
			Name: "step 1: input int and return int",
			Func: func(a int) int { return a + 42 },
		},
		{
			Name: "step 2: input int and return string",
			Func: func(a int) string {
				if a == 42 {
					panic("bingo - found desired panic after finding 42")
				}
				return strconv.Itoa(a)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We create an Fuzzer, but we don't rely on the data []byte in this test
			// because we force a Plan, so we use an empty data []byte here.
			fz := NewFuzzer([]byte{})

			// Success is currently not panicking in reflect or similar,
			// while panicking with an expected "bingo" panic if we set up the
			// test case to do that via a properly working chain.
			// TODO: could get the return value back and validate, though would
			// also probably want to force the input arg not to be zero (e.g., construct a data []byte, or ...)
			if tt.wantBingo {
				defer func() {
					err := recover()
					s, ok := err.(string)
					if ok && strings.Contains(s, "bingo") {
						t.Logf("expected panic occurred: %v", err)
					} else {
						t.Error("did not get expected panic")
					}
				}()
			}

			fz.chain(steps, tt.pl)
		})
	}
}

// fakeFill is a simple test standin for fzgen/fuzzer.Fuzzer.Fill.
// must take pointer to value of interest. For example, to fill an int:
//     var a int
//     fakeFill(&a)
func fakeFill(args ...interface{}) {
	for _, obj := range args {
		answer := 42
		switch v := obj.(type) {
		case *int: // handles an int parameter in a Step.Func
			*v = answer
		case **int: // handles an *int parameter in a Step.Func
			*v = new(int)
			**v = answer
		case *io.Reader: // handles an io.Reader parameter in a Step.Func
			var b []byte
			b = append(b, byte(answer))
			// to actually fill: fz.Fill(&b)
			*v = bytes.NewReader(b)
		default:
			panic(fmt.Sprintf("unsupported type in fakeFill: %T %v", obj, obj))
		}
	}
}

func TestFuzzerFill(t *testing.T) {
	t.Run("int32 - 4 byte input", func(t *testing.T) {
		input := []byte{0x0, 0x42, 0x0, 0x0, 0x0}
		want := int32(0x42)

		fz := NewFuzzer(input)
		var got int32
		fz.Fill(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("int32 - 1 byte input", func(t *testing.T) {
		input := []byte{0x0, 0x42}
		want := int32(0x0)

		fz := NewFuzzer(input)
		var got int32
		fz.Fill(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestCalcParallelPair(t *testing.T) {
	tests := []struct {
		name                   string
		parallelPlan           byte
		execCallLen            int
		wantStartParallelIndex int
		wantStopParallelIndex  int
	}{
		{"1", '1', 10, 8, 9},
		{"2", '2', 10, 7, 8},
		{"9", '9', 10, 0, 1},
		{"9+1", '9' + 1, 10, 8, 9},
		{"wrap", 0, 10, 8, 9},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStartParallelIndex, gotStopParallelIndex := calcParallelPair(tt.parallelPlan, tt.execCallLen)
			if gotStartParallelIndex != tt.wantStartParallelIndex {
				t.Errorf("calcParallelIndex() startParallelIndex = %v, want %v", gotStartParallelIndex, tt.wantStartParallelIndex)
			}
			if gotStopParallelIndex != tt.wantStopParallelIndex {
				t.Errorf("calcParallelIndex() stopParallelIndex = %v, want %v", gotStopParallelIndex, tt.wantStopParallelIndex)
			}
		})
	}
}

func TestCalcParallelN(t *testing.T) {
	tests := []struct {
		name                   string
		parallelPlan           byte
		execCallLen            int
		wantStartParallelIndex int
		wantStopParallelIndex  int
	}{
		{"0", 0, 10, 8, 9},
		{"1", 1, 10, 7, 9},
		{"8", 8, 10, 0, 9},
		{"9", 9, 10, 8, 9},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStartParallelIndex, gotStopParallelIndex := calcParallelN(tt.parallelPlan, tt.execCallLen)
			if gotStartParallelIndex != tt.wantStartParallelIndex {
				t.Errorf("calcParallelIndex() startParallelIndex = %v, want %v", gotStartParallelIndex, tt.wantStartParallelIndex)
			}
			if gotStopParallelIndex != tt.wantStopParallelIndex {
				t.Errorf("calcParallelIndex() stopParallelIndex = %v, want %v", gotStopParallelIndex, tt.wantStopParallelIndex)
			}
		})
	}
}
