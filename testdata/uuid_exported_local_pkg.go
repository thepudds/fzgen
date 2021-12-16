package uuid

// if needed, fill in imports or run 'goimports'
import (
	"fmt"
	"reflect"
	"testing"

	"github.com/thepudds/fzgen/fuzzer"
)

func Fuzz_NewFromBytes_Chain(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var b []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&b)

		target, err := NewFromBytes(b)
		if err != nil {
			return
		}

		steps := []fuzzer.Step{
			{
				Name: "Fuzz_MyUUID_UnmarshalBinary",
				Func: func(d1 []byte) {
					target.UnmarshalBinary(d1)
				},
			},
			{
				Name: "Fuzz_MyUUID_MarshalBinary",
				Func: func() ([]byte, error) {
					return target.MarshalBinary()
				},
			},
			{
				Name: "Fuzz_MyUUID_URN",
				Func: func() string {
					return target.URN()
				},
			},
		}

		// Execute a specific chain of steps, with the count, sequence and arguments controlled by fz.Chain
		fz.Chain(steps, fuzzer.ChainParallel)

		// Validate with some roundtrip checks. These can be edited or deleted if not appropriate for your target.
		// Check MarshalBinary.
		result2, err := target.MarshalBinary()
		if err != nil {
			// Some targets should never return an error here for an object created by a constructor.
			// If that is the case for your target, you can change this to a panic(err) or t.Fatal.
			return
		}

		// Check UnmarshalBinary.
		var tmp2 MyUUID
		err = tmp2.UnmarshalBinary(result2)
		if err != nil {
			panic(fmt.Sprintf("UnmarshalBinary failed after successful MarshalBinary. original: %v %#v marshalled: %q error: %v", target, target, result2, err))
		}
		if !reflect.DeepEqual(target, tmp2) {
			panic(fmt.Sprintf("MarshalBinary/UnmarshalBinary roundtrip equality failed. original: %v %#v marshalled: %q unmarshalled: %v %#v",
				target, target, result2, tmp2, tmp2))
		}
	})
}
