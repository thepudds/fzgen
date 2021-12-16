package netlinkfuzz // rename if needed

// if needed, fill in imports or run 'goimports'
import (
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/thepudds/fzgen/fuzzer"
)

func Fuzz_NewAttributeDecoder_Chain(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var b []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&b)

		target, err := netlink.NewAttributeDecoder(b)
		if err != nil {
			return
		}

		steps := []fuzzer.Step{
			fuzzer.Step{
				Name: "Fuzz_AttributeDecoder_Bytes",
				Func: func() []byte {
					return target.Bytes()
				}},
			// skipping Fuzz_AttributeDecoder_Do because parameters include unsupported func or chan: func(b []byte) error

			fuzzer.Step{
				Name: "Fuzz_AttributeDecoder_Err",
				Func: func() {
					target.Err()
				}},
			fuzzer.Step{
				Name: "Fuzz_AttributeDecoder_Flag",
				Func: func() bool {
					return target.Flag()
				}},
			fuzzer.Step{
				Name: "Fuzz_AttributeDecoder_Int16",
				Func: func() int16 {
					return target.Int16()
				}},
			fuzzer.Step{
				Name: "Fuzz_AttributeDecoder_Int32",
				Func: func() int32 {
					return target.Int32()
				}},
			fuzzer.Step{
				Name: "Fuzz_AttributeDecoder_Int64",
				Func: func() int64 {
					return target.Int64()
				}},
			fuzzer.Step{
				Name: "Fuzz_AttributeDecoder_Int8",
				Func: func() int8 {
					return target.Int8()
				}},
			fuzzer.Step{
				Name: "Fuzz_AttributeDecoder_Len",
				Func: func() int {
					return target.Len()
				}},
			// skipping Fuzz_AttributeDecoder_Nested because parameters include unsupported func or chan: func(nad *github.com/mdlayher/netlink.AttributeDecoder) error

			fuzzer.Step{
				Name: "Fuzz_AttributeDecoder_Next",
				Func: func() bool {
					return target.Next()
				}},
			fuzzer.Step{
				Name: "Fuzz_AttributeDecoder_String",
				Func: func() string {
					return target.String()
				}},
			fuzzer.Step{
				Name: "Fuzz_AttributeDecoder_Type",
				Func: func() uint16 {
					return target.Type()
				}},
			fuzzer.Step{
				Name: "Fuzz_AttributeDecoder_TypeFlags",
				Func: func() uint16 {
					return target.TypeFlags()
				}},
			fuzzer.Step{
				Name: "Fuzz_AttributeDecoder_Uint16",
				Func: func() uint16 {
					return target.Uint16()
				}},
			fuzzer.Step{
				Name: "Fuzz_AttributeDecoder_Uint32",
				Func: func() uint32 {
					return target.Uint32()
				}},
			fuzzer.Step{
				Name: "Fuzz_AttributeDecoder_Uint64",
				Func: func() uint64 {
					return target.Uint64()
				}},
			fuzzer.Step{
				Name: "Fuzz_AttributeDecoder_Uint8",
				Func: func() uint8 {
					return target.Uint8()
				}},
		}

		// Execute a specific chain of steps, with the count, sequence and arguments controlled by fz.Chain
		fz.Chain(steps)
	})
}
