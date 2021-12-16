package roaringfuzz // rename if needed

// if needed, fill in imports or run 'goimports'
import (
	"io"
	"testing"

	"github.com/RoaringBitmap/roaring"
	"github.com/thepudds/fzgen/fuzzer"
)

func Fuzz_NewBitmap_Chain(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		fz := fuzzer.NewFuzzer(data)

		target := roaring.NewBitmap()

		steps := []fuzzer.Step{
			fuzzer.Step{
				Name: "Fuzz_Bitmap_Add",
				Func: func(x uint32) {
					target.Add(x)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_AddInt",
				Func: func(x int) {
					target.AddInt(x)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_AddMany",
				Func: func(dat []uint32) {
					target.AddMany(dat)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_AddRange",
				Func: func(rangeStart uint64, rangeEnd uint64) {
					target.AddRange(rangeStart, rangeEnd)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_And",
				Func: func(x2 *roaring.Bitmap) {
					target.And(x2)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_AndAny",
				Func: func(bitmaps []*roaring.Bitmap) {
					target.AndAny(bitmaps...)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_AndCardinality",
				Func: func(x2 *roaring.Bitmap) uint64 {
					return target.AndCardinality(x2)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_AndNot",
				Func: func(x2 *roaring.Bitmap) {
					target.AndNot(x2)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_CheckedAdd",
				Func: func(x uint32) bool {
					return target.CheckedAdd(x)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_CheckedRemove",
				Func: func(x uint32) bool {
					return target.CheckedRemove(x)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_Clear",
				Func: func() {
					target.Clear()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_Clone",
				Func: func() *roaring.Bitmap {
					return target.Clone()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_CloneCopyOnWriteContainers",
				Func: func() {
					target.CloneCopyOnWriteContainers()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_Contains",
				Func: func(x uint32) bool {
					return target.Contains(x)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_ContainsInt",
				Func: func(x int) bool {
					return target.ContainsInt(x)
				}},
			// skipping Fuzz_Bitmap_Equals because parameters include unsupported interface: interface{}

			fuzzer.Step{
				Name: "Fuzz_Bitmap_Flip",
				Func: func(rangeStart uint64, rangeEnd uint64) {
					target.Flip(rangeStart, rangeEnd)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_FlipInt",
				Func: func(rangeStart int, rangeEnd int) {
					target.FlipInt(rangeStart, rangeEnd)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_Freeze",
				Func: func() ([]byte, error) {
					return target.Freeze()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_FreezeTo",
				Func: func(buf []byte) (int, error) {
					return target.FreezeTo(buf)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_FromBase64",
				Func: func(str string) (int64, error) {
					return target.FromBase64(str)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_FromBuffer",
				Func: func(buf []byte) (int64, error) {
					return target.FromBuffer(buf)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_FrozenView",
				Func: func(buf []byte) {
					target.FrozenView(buf)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_GetCardinality",
				Func: func() uint64 {
					return target.GetCardinality()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_GetCopyOnWrite",
				Func: func() bool {
					return target.GetCopyOnWrite()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_GetFrozenSizeInBytes",
				Func: func() uint64 {
					return target.GetFrozenSizeInBytes()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_GetSerializedSizeInBytes",
				Func: func() uint64 {
					return target.GetSerializedSizeInBytes()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_GetSizeInBytes",
				Func: func() uint64 {
					return target.GetSizeInBytes()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_HasRunCompression",
				Func: func() bool {
					return target.HasRunCompression()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_Intersects",
				Func: func(x2 *roaring.Bitmap) bool {
					return target.Intersects(x2)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_IsEmpty",
				Func: func() bool {
					return target.IsEmpty()
				}},
			// skipping Fuzz_Bitmap_Iterate because parameters include unsupported func or chan: func(x uint32) bool

			fuzzer.Step{
				Name: "Fuzz_Bitmap_Iterator",
				Func: func() roaring.IntPeekable {
					return target.Iterator()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_ManyIterator",
				Func: func() roaring.ManyIntIterable {
					return target.ManyIterator()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_MarshalBinary",
				Func: func() ([]byte, error) {
					return target.MarshalBinary()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_Maximum",
				Func: func() uint32 {
					return target.Maximum()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_Minimum",
				Func: func() uint32 {
					return target.Minimum()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_Or",
				Func: func(x2 *roaring.Bitmap) {
					target.Or(x2)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_OrCardinality",
				Func: func(x2 *roaring.Bitmap) uint64 {
					return target.OrCardinality(x2)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_Rank",
				Func: func(x uint32) uint64 {
					return target.Rank(x)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_ReadFrom",
				Func: func(reader io.Reader, cookieHeader []byte) (int64, error) {
					return target.ReadFrom(reader, cookieHeader...)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_Remove",
				Func: func(x uint32) {
					target.Remove(x)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_RemoveRange",
				Func: func(rangeStart uint64, rangeEnd uint64) {
					target.RemoveRange(rangeStart, rangeEnd)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_ReverseIterator",
				Func: func() roaring.IntIterable {
					return target.ReverseIterator()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_RunOptimize",
				Func: func() {
					target.RunOptimize()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_Select",
				Func: func(x uint32) (uint32, error) {
					return target.Select(x)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_SetCopyOnWrite",
				Func: func(val bool) {
					target.SetCopyOnWrite(val)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_Stats",
				Func: func() roaring.Statistics {
					return target.Stats()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_String",
				Func: func() string {
					return target.String()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_ToArray",
				Func: func() []uint32 {
					return target.ToArray()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_ToBase64",
				Func: func() (string, error) {
					return target.ToBase64()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_ToBytes",
				Func: func() ([]byte, error) {
					return target.ToBytes()
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_UnmarshalBinary",
				Func: func(d1 []byte) {
					target.UnmarshalBinary(d1)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_WriteTo",
				Func: func(stream io.Writer) (int64, error) {
					return target.WriteTo(stream)
				}},
			fuzzer.Step{
				Name: "Fuzz_Bitmap_Xor",
				Func: func(x2 *roaring.Bitmap) {
					target.Xor(x2)
				}},
		}

		// Execute a specific chain of steps, with the count, sequence and arguments controlled by fz.Chain
		fz.Chain(steps)
	})
}
