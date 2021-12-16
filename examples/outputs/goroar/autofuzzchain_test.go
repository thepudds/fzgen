package goroarfuzz // rename if needed

// if needed, fill in imports or run 'goimports'
import (
	"testing"

	"github.com/fzandona/goroar"
	"github.com/thepudds/fzgen/fuzzer"
)

func Fuzz_New_Chain(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fz := fuzzer.NewFuzzer(data)

		target := goroar.New()
		other := goroar.New()

		steps := []fuzzer.Step{
			fuzzer.Step{
				Name: "Fuzz_RoaringBitmap_Add",
				Func: func(x uint32) {
					target.Add(x)
				}},
			fuzzer.Step{
				Name: "Fuzz_RoaringBitmap_Add_Other",
				Func: func(x uint32) {
					other.Add(x)
				}},
			fuzzer.Step{
				Name: "Fuzz_RoaringBitmap_And",
				Func: func() {
					target.And(other)
				}},
			fuzzer.Step{
				Name: "Fuzz_RoaringBitmap_AndNot",
				Func: func() {
					target.AndNot(other)
				}},
			fuzzer.Step{
				Name: "Fuzz_RoaringBitmap_Cardinality",
				Func: func() int {
					return target.Cardinality()
				}},
			fuzzer.Step{
				Name: "Fuzz_RoaringBitmap_Cardinality_Other",
				Func: func() int {
					return other.Cardinality()
				}},
			fuzzer.Step{
				Name: "Fuzz_RoaringBitmap_Clone",
				Func: func() *goroar.RoaringBitmap {
					return target.Clone()
				}},
			fuzzer.Step{
				Name: "Fuzz_RoaringBitmap_Clone_Other",
				Func: func() *goroar.RoaringBitmap {
					return other.Clone()
				}},
			fuzzer.Step{
				Name: "Fuzz_RoaringBitmap_Contains",
				Func: func(i uint32) bool {
					return target.Contains(i)
				}},
/*
			fuzzer.Step{
				Name: "Fuzz_RoaringBitmap_Iterator",
				Func: func() <-chan uint32 {
					return target.Iterator()
				}},
*/
			fuzzer.Step{
				Name: "Fuzz_RoaringBitmap_Or",
				Func: func() {
					target.Or(other)
				}},
			fuzzer.Step{
				Name: "Fuzz_RoaringBitmap_SizeInBytes",
				Func: func() int {
					return target.SizeInBytes()
				}},
			fuzzer.Step{
				Name: "Fuzz_RoaringBitmap_Stats",
				Func: func() {
					target.Stats()
				}},
			fuzzer.Step{
				Name: "Fuzz_RoaringBitmap_String",
				Func: func() string {
					return target.String()
				}},
			fuzzer.Step{
				Name: "Fuzz_RoaringBitmap_Xor",
				Func: func() {
					target.Xor(other)
				}},
		}

		// Execute a specific chain of steps, with the count, sequence and arguments controlled by fz.Chain
		fz.Chain(steps)
	})
}
