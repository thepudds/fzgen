// Package randparam allows a []byte to be used as a source of random parameter values.
//
// The primary use case is to allow thepudds/fzgen to automatically generate fuzzing functions
// for rich signatures such as:
//    regexp.MatchReader(pattern string, r io.RuneReader)
//
// randparam fills in common top-level interfaces such as io.Reader, io.Writer, io.ReadWriter, and so on.
// See SupportedInterfaces for current list.
//
// This package predates builtin cmd/go fuzzing support, and originally
// was targeted at use by thepudds/fzgo, which was a working prototype of an earlier "first class fuzzing in cmd/go" proposal,
// (There is still some baggage left over from that earlier world).
package randparam

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"reflect"
)

// SupportedInterfaces enumerates interfaces that can be filled by Fill(&obj).
var SupportedInterfaces = map[string]bool{
	"io.Writer":       true,
	"io.Reader":       true,
	"io.ReaderAt":     true,
	"io.WriterTo":     true,
	"io.Seeker":       true,
	"io.ByteScanner":  true,
	"io.RuneScanner":  true,
	"io.ReadSeeker":   true,
	"io.ByteReader":   true,
	"io.RuneReader":   true,
	"io.ByteWriter":   true,
	"io.ReadWriter":   true,
	"io.ReaderFrom":   true,
	"io.StringWriter": true,
	"io.Closer":       true,
	"io.ReadCloser":   true,
	"context.Context": true,
}

// Fuzzer generates random values for public members.
// It allows wiring together cmd/go fuzzing or dvyukov/go-fuzz (for randomness, instrumentation, managing corpus, etc.)
// with the ability to fill in common interfaces, as well as string, []byte, and number values.
type Fuzzer struct {
	fzgoSrc *randSource
}

// NewFuzzer returns a *Fuzzer, initialized with the []byte as an input stream for drawing values via rand.Rand.
func NewFuzzer(data []byte) *Fuzzer {
	// create our random data stream that fill use data []byte for results.
	fzgoSrc := &randSource{data}

	f := &Fuzzer{
		fzgoSrc: fzgoSrc,
	}

	// TODO: probably have parameters for number of elements.NilChance, NumElements, e.g.:
	// Initially allowing too much variability with NumElements seemed
	// to be a problem, but more likely that was an early indication of
	// the need to better tune the exact string/[]byte encoding to work
	// better with sonar.

	// TODO: consider if we want to use the first byte for meta parameters like
	// forcing count of slices like we used to do in fzgo.and so.
	// We still draw the first byte here to reserve it.
	fzgoSrc.Byte()

	// TODO: probably delete the alternative string encoding code.
	// Probably DON'T have different string encodings.
	// (I suspect it helped the fuzzer get 'stuck' if there multiple ways
	// to encode same "interesting" inputs).
	// if bits.OnesCount8(firstByte)%2 == 0 {
	// 	fzgoSrc.lengthEncodedStrings = false
	// }

	return f
}

// Remaining reports how many bytes remain in our original input []byte.
func (f *Fuzzer) Remaining() int {
	return f.fzgoSrc.Remaining()
}

// Drain removes the next n bytes from the input []byte.
// If n is greater than Remaining, it drains all remaining bytes.
func (f *Fuzzer) Drain(n int) {
	f.fzgoSrc.Drain(n)
}

// Data returns a []byte covering the remaining bytes from
// the original input []byte. Any bytes that are considered
// consumed should be indicated via Drain.
func (f *Fuzzer) Data() []byte {
	return f.fzgoSrc.Data()
}

// fillInterface reports if it has filled an interface pointer.
//
// Note: keep in sync with SupportedInterfaces (TODO: consider making dynamic).
//
// Rough counts of most common interfaces in public funcs/methods For stdlib
//   (based on output from early version of fzgo that skipped all interfaces):
//   $ grep -r 'skipping' | awk '{print $10}'  | grep -v 'func' | sort | uniq -c | sort -rn | head -20
// 		146 io.Writer
// 		122 io.Reader
// 		 75 reflect.Type
// 		 64 go/types.Type
// 		 55 interface{}
// 		 44 context.Context
// 		 41 []interface{}
// 		 22 go/constant.Value
// 		 17 net.Conn
// 		 17 math/rand.Source
// 		 16 net/http.ResponseWriter
// 		 16 net/http.Handler
// 		 16 image/color.Color
// 		 13 io.ReadWriteCloser
// 		 13 error
// 		 12 image/color.Palette
// 		 11 io.ReaderAt
// 		  9 crypto/cipher.Block
// 		  8 net.Listener
// 		  6 go/ast.Node
//
func (f *Fuzzer) fillInterface(obj interface{}) bool {
	var b []byte
	switch v := obj.(type) {
	// Cases using bytes.NewReader
	case *io.Reader:
		f.Fill(&b)
		*v = bytes.NewReader(b)
	case *io.ReaderAt:
		f.Fill(&b)
		*v = bytes.NewReader(b)
	case *io.WriterTo:
		f.Fill(&b)
		*v = bytes.NewReader(b)
	case *io.Seeker:
		f.Fill(&b)
		*v = bytes.NewReader(b)
	case *io.ByteScanner:
		f.Fill(&b)
		*v = bytes.NewReader(b)
	case *io.RuneScanner:
		f.Fill(&b)
		*v = bytes.NewReader(b)
	case *io.ReadSeeker:
		f.Fill(&b)
		*v = bytes.NewReader(b)
	case *io.ByteReader:
		f.Fill(&b)
		*v = bytes.NewReader(b)
	case *io.RuneReader:
		f.Fill(&b)
		*v = bytes.NewReader(b)

	// Cases using bytes.NewBuffer
	case *io.ByteWriter:
		f.Fill(&b)
		*v = bytes.NewBuffer(b)
	case *io.ReadWriter: // TODO: consider a bytes.Reader + ioutil.Discard?
		f.Fill(&b)
		*v = bytes.NewBuffer(b)
	case *io.ReaderFrom:
		f.Fill(&b)
		*v = bytes.NewBuffer(b)
	case *io.StringWriter:
		f.Fill(&b)
		*v = bytes.NewBuffer(b)

	// Cases using ioutil.NopCloser(bytes.NewReader)
	case *io.Closer:
		f.Fill(&b)
		*v = ioutil.NopCloser(bytes.NewReader(b))
	case *io.ReadCloser:
		f.Fill(&b)
		*v = ioutil.NopCloser(bytes.NewReader(b))

	// Cases using context.Background
	case *context.Context:
		*v = context.Background()

	// No match
	default:
		return false
	}
	return true
}

// fillByteSlice is a custom fill function so that we have exact control over how
// strings and []byte are encoded.
//
// fillByteSlice generates a byte slice using the input []byte stream.
// []byte are deserialized as length encoded, where a leading byte
// encodes the length in range [0-255], but the exact interpretation is a little subtle.
// There is surely room for improvement here, but this current approach is the result of some
// some basic experimentation with some different alternatives, with this approach
// yielding decent results in terms of fuzzing efficiency on basic tests,
// so using this approach at least for now.
//
// The current approach:
//
// 1. Do not use 0x0 to encode a zero length string (or zero length []byte).
//
// We need some way to encode nil byte slices and empty strings
// in the input data []byte. Using 0x0 is the obvious way to encode
// a zero length, but that was not a good choice based on some experimentation.
// I suspect partly because fuzzers (e.g,. go-fuzz) like to insert zeros,
// but more importantly because a 0x0 length field does not give go-fuzz sonar
// anything to work with when looking to substitute a value back in.
// If sonar sees [0x1][0x42] in the input data, and observes 0x42 being used live
// in a string comparison against the value "bingo", sonar can update the data
// to be [0x5][b][i][n][g][o] based on finding the 0x42 and guessing the 0x1
// is a length field that it then updates. In contrast, if sonar sees [0x0] in the input
// data and observes "" being used in a string comparison against "bingo",
// sonar can't currently hunt to find "" in the input data (though I suspect in
// theory sonar could be updated to look for a 0x0 and guess it is a zero length string).
// Net, we want something other than 0x0 to indicate a zero length string or byte slice.
// We pick 0xFF to indicate a zero length.
//
// 2. Do not cap the size at the bytes remaining.
//
// I suspect that also interferes with go-fuzz sonar, which attempts
// to find length fields to adjust when substituting literals.
// If we cap the number of bytes, it means the length field in the input []byte
// would not agree with the actual length used, which means
// sonar does not adjust the length field correctly.
// A concrete example is that if we were to cap the size of what we read,
// the meaning of [0xF1][0x1][0x2][EOD] would change once new data is appended,
// but more importantly sonar would not properly adjust the 0xF1 as a length
// field if sonar substituted in a more interesting string value in place of [0x1][0x2].
//
// 3. Do not drawing zeros past the end of the input []byte.
//
// This is similar reasons as 1 and 2. Drawing zeros past the end
// also means a value that shows  up in the live code under test
// does not have a byte-for-byte match with something in the input []byte.
//
// 4. Skip over any 0x0 byte values that would otherwise have been a size field.
//
// This is effectively an implementation detail of 1. In other words,
// if we don't use 0x0 to ecode a zero length string, we need to do
// something when we find a 0x0 in the spot where a length field would go.
//
// Summary: one way to think about it is the encoding of a length field is:
//      * 0-N 0x0 bytes prior to a non-zero byte, and
//      * that non-zero byte is the actual length used, unless that non-zero byte
//	      is 0xFF, in which case that signals a zero-length string/[]byte, and
//      * the length value used must be able to draw enough real random bytes from the input []byte.
func (f *Fuzzer) fillByteSlice(ptr *[]byte) {
	verbose := false // TODO: probably remove eventually.
	if verbose {
		fmt.Println("randBytes verbose:", verbose)
	}

	var bs []byte
	var size int

	// try to find a size field.
	// this is slightly more subtle than just reading one byte,
	// mainly in order to better work with go-fuzz sonar.
	// see long comment above.
	for {
		if f.Remaining() == 0 {
			if verbose {
				fmt.Println("ran out of bytes, 0 remaining")
			}
			// return nil slice (which will be empty string for string)
			*ptr = nil
			return
		}

		// draw a size in [0, 255] from our input byte[] stream
		sizeField := int(f.fzgoSrc.Byte())
		if verbose {
			fmt.Println("sizeField:", sizeField)
		}

		// If we don't have enough data, we want to
		// *not* use the size field or the data after sizeField,
		// in order to work better with sonar.
		if sizeField > f.Remaining() {
			if verbose {
				fmt.Printf("%d bytes requested via size field, %d remaining, drain rest\n",
					sizeField, f.Remaining())
			}
			// return nil slice (which will be empty string for string).
			// however, before we return, we consume all of our remaining bytes.
			f.Drain(f.Remaining())

			*ptr = nil
			return
		}

		// skip over any zero bytes for our size field
		// In other words, the encoding is 0-N 0x0 bytes prior to a useful length
		// field we will use.
		if sizeField == 0x0 {
			continue
		}

		// 0xFF is our chosen value to represent a zero length string/[]byte.
		// (See long comment above for some rationale).
		if sizeField == 0xFF {
			size = 0
		} else {
			size = sizeField
		}

		// found a usable, non-zero sizeField. let's move on to use it on the next bytes!
		break
	}

	bs = make([]byte, size)
	for i := range bs {
		bs[i] = f.fzgoSrc.Byte()
	}
	*ptr = bs
}

// fillString is a custom fill function so that we have exact control over how
// strings are encoded. It is a thin wrapper over randBytes.
func (f *Fuzzer) fillString(s *string) {
	var bs []byte
	f.fillByteSlice(&bs)
	*s = string(bs)
}

// TODO: this might be temporary. Here we handle slices of strings as a preview of
// some possible performance improvements.
func (f *Fuzzer) fillStringSlice(s *[]string) {
	size, ok := f.calcSize(f.fzgoSrc)
	if !ok {
		*s = nil
		return
	}
	ss := make([]string, size)
	for i := range ss {
		var str string
		f.fillString(&str)
		ss[i] = str
	}
	*s = ss
}

// TODO: temporarily extracted this from randBytes. Decide to drop vs. keep/unify.
func (f *Fuzzer) calcSize(fzgoSrc *randSource) (size int, ok bool) {
	verbose := false // TODO: probably remove eventually.

	// try to find a size field.
	// this is slightly more subtle than just reading one byte,
	// mainly in order to better work with go-fuzz sonar.
	// see long comment above.
	for {
		if f.Remaining() == 0 {
			if verbose {
				fmt.Println("ran out of bytes, 0 remaining")
			}
			// return nil slice (which will be empty string for string)

			return 0, false
		}

		// draw a size in [0, 255] from our input byte[] stream
		sizeField := int(f.fzgoSrc.Byte())
		if verbose {
			fmt.Println("sizeField:", sizeField)
		}

		// If we don't have enough data, we want to
		// *not* use the size field or the data after sizeField,
		// in order to work better with sonar.
		if sizeField > f.fzgoSrc.Remaining() {
			if verbose {
				fmt.Printf("%d bytes requested via size field, %d remaining, drain rest\n",
					sizeField, fzgoSrc.Remaining())
			}
			// return nil slice (which will be empty string for string).
			// however, before we return, we consume all of our remaining bytes.
			fzgoSrc.Drain(fzgoSrc.Remaining())

			return 0, false
		}

		// skip over any zero bytes for our size field
		// In other words, the encoding is 0-N 0x0 bytes prior to a useful length
		// field we will use.
		if sizeField == 0x0 {
			continue
		}

		// 0xFF is our chosen value to represent a zero length string/[]byte.
		// (See long comment above for some rationale).
		if sizeField == 0xFF {
			size = 0
		} else {
			size = sizeField
		}

		// found a usable, non-zero sizeField. let's move on to use it on the next bytes!
		break
	}
	return size, true
}

// =================== TEMP ===================

// TODO: delete old implementation
// // bytesToConsume calculates the bytes that should be
// // used for a given numeric reflect.Value, and panics otherwise.
// // reflect.Int always uses 8 bytes for consistency  across platforms.
// func kindNumericSize(k reflect.Kind) int {
// 	// recall, byte and rune are type aliases, and hence are convered.
// 	switch k {
// 	case reflect.Int, reflect.Int64, reflect.Uint64, reflect.Float64:
// 		return 8
// 	case reflect.Int32, reflect.Uint32, reflect.Float32:
// 		return 4
// 	case reflect.Int16, reflect.Uint16:
// 		return 2
// 	case reflect.Int8, reflect.Uint8:
// 		return 1
// 	default:
// 		panic(fmt.Sprintf("fzgen: kindBytes: unexpected kind %v", k))
// 	}
// }

// TODO: delete old implementations
// func (f *Fuzzer) fillNumeric(v reflect.Value) {
// 	bits := f.numericDraw(v.Kind())

// 	// recall, byte and rune are type aliases, and hence are convered.
// 	switch v.Kind() {
// 	case reflect.Int, reflect.Int64, reflect.Int32, reflect.Int16, reflect.Int8:
// 		v.SetInt(int64(bits))
// 	case reflect.Uint, reflect.Uint64, reflect.Uint32, reflect.Uint16, reflect.Uint8:
// 		v.SetUint(bits)
// 	case reflect.Float64:
// 		v.SetFloat(math.Float64frombits(bits))
// 	case reflect.Float32:
// 		v.SetFloat(float64(math.Float32frombits(uint32(bits))))
// 	case reflect.Complex128, reflect.Complex64:
// 		// TODO: handle complex?
// 		panic("fzgen: fillNumeric: complex not yet implemented")
// 	default:
// 		panic(fmt.Sprintf("fzgen: fillNumeric: unexpected kind %v for value %v of type %v", v.Kind(), v, v.Type()))
// 	}
// }

// TODO: delete old implementation
// func (f *Fuzzer) fillInt64(v reflect.Value) {
// 	consume := kindNumericSize(v.Kind())
// 	if f.Remaining() < consume {
// 		v.SetInt(0)
// 		return
// 	}
// 	var i int64
// 	b := f.Data()[:consume]
// 	f.Drain(consume)
// 	buf := bytes.NewReader(b)
// 	binary.Read(buf, binary.LittleEndian, &i)
// 	// i := int64(binary.LittleEndian.Uint64(b))
// 	v.SetInt(i)
// }

func (f *Fuzzer) Fill(obj interface{}) {
	f.Fill2(obj)
}

func (f *Fuzzer) Fill2(obj interface{}) {
	v := reflect.ValueOf(obj)
	if v.Kind() != reflect.Ptr {
		panic("fzgen: Fill requires pointers")
	}
	// indirect through pointer, and rescursively fill
	v = v.Elem()
	f.fill(v, 0, fillOpts{})
}

type fillOpts struct {
	panicOnUnsupported bool
}

func (f *Fuzzer) fill(v reflect.Value, depth int, opts fillOpts) {
	depth++
	if depth > 10 {
		return
	}

	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// recall, rune is type alias of int32.
		bits := f.numericDraw(v.Kind())
		v.SetInt(int64(bits))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		// recall, byte is type alias of uint8.
		bits := f.numericDraw(v.Kind())
		v.SetUint(bits)
	case reflect.Float32:
		bits := f.numericDraw(v.Kind())
		v.SetFloat(float64(math.Float32frombits(uint32(bits))))
	case reflect.Float64:
		bits := f.numericDraw(v.Kind())
		v.SetFloat(math.Float64frombits(bits))
	case reflect.Complex64, reflect.Complex128:
		var a, b float64
		f.Fill(&a)
		f.Fill(&b)
		v.SetComplex(complex(a, b))
	case reflect.String:
		var s string
		f.fillString(&s)
		v.SetString(s)
	case reflect.Bool:
		var b byte
		f.Fill(&b)
		if b < 128 {
			v.SetBool(false)
		} else {
			v.SetBool(true)
		}
	case reflect.Array:
		if v.Type().Elem().String() == "uint8" {
			// TODO: does this help? This is not consistent with other types, but we don't know size of elements for most other
			// types (e.g., could be array of structs that have strings).
			// At least for now, make it behave like older byte array fill, which only filled if there was enough
			// remaining in the input data []byte.
			if f.Remaining() < v.Len() {
				break
			}
		}
		for i := 0; i < v.Len(); i++ {
			f.fill(v.Index(i), depth, opts)
		}
	case reflect.Slice:
		if v.Type().Elem().String() == "uint8" {
			var b []byte
			f.fillByteSlice(&b)
			v.Set(reflect.MakeSlice(v.Type(), len(b), len(b)))
			for i := 0; i < v.Len(); i++ {
				v.Index(i).SetUint(uint64(b[i]))
			}
		} else {
			// TODO: favor smaller slice sizes?
			// TODO: make slice size for non-byte slices more controllable via config. max is 10 for now.
			var size byte
			f.Fill(&size)
			size %= 10
			v.Set(reflect.MakeSlice(v.Type(), int(size), int(size)))
			for i := 0; i < v.Len(); i++ {
				f.fill(v.Index(i), depth, opts)
			}
		}
	case reflect.Map:
		// TODO: similar to slice - favor smaller, more configurable
		var size byte
		f.Fill(&size)
		size %= 10
		v.Set(reflect.MakeMapWithSize(v.Type(), int(size)))
		for i := 0; i < int(size); i++ {
			key := reflect.New(v.Type().Key()).Elem()
			value := reflect.New(v.Type().Elem()).Elem()
			f.fill(key, depth, opts)
			f.fill(value, depth, opts)
			v.SetMapIndex(key, value)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).CanSet() {
				// TODO: could consider option for unexported fields
				f.fill(v.Field(i), depth, opts)
			}
		}
	case reflect.Interface:
		// get back the &interface{}.
		iface := v.Addr().Interface()
		// see if we can fill it.
		success := f.fillInterface(iface)
		if !success && opts.panicOnUnsupported {
			panic(fmt.Sprintf("fzgen: fill: unsupported interface kind %v for value %v of type %v", v.Kind(), v, v.Type()))
		}
	case reflect.Ptr:
		// create a zero value elem, then recursively fill that
		v.Set(reflect.New(v.Type().Elem()))
		f.fill(v.Elem(), depth, opts)
	case reflect.Uintptr, reflect.Chan, reflect.Func, reflect.UnsafePointer:
		if opts.panicOnUnsupported {
			panic(fmt.Sprintf("fzgen: fill: unsupported kind %v for value %v of type %v", v.Kind(), v, v.Type()))
		}
	case reflect.Invalid:
		panic("fzgen: fill: reflect.Invalid object")
	default:
		panic(fmt.Sprintf("fzgen: fill: unexpected kind %v for value %v of type %v", v.Kind(), v, v.Type()))
	}
}

// numericDraw calculates the bytes that should be
// used for a given numeric reflect.Value. If there are not enough bytes
// remaining in our data []byte, returns 0. Otherwise, returns
// the bits corresponding to the proper size.
// reflect.Int always uses 8 bytes for consistency across platforms.
// This panics if not a numeric kind, or if called for a complex kind.
// For complex kinds, instead draw two floats.
func (f *Fuzzer) numericDraw(k reflect.Kind) (bits uint64) {
	switch k {
	case reflect.Int, reflect.Int64, reflect.Uint64, reflect.Float64:
		// reflect.Int always uses 8 bytes for consistency  across platforms.
		if f.Remaining() < 8 {
			return 0
		}
		bits = uint64(f.fzgoSrc.Byte()) |
			uint64(f.fzgoSrc.Byte())<<8 |
			uint64(f.fzgoSrc.Byte())<<16 |
			uint64(f.fzgoSrc.Byte())<<24 |
			uint64(f.fzgoSrc.Byte())<<32 |
			uint64(f.fzgoSrc.Byte())<<40 |
			uint64(f.fzgoSrc.Byte())<<48 |
			uint64(f.fzgoSrc.Byte())<<56
	case reflect.Int32, reflect.Uint32, reflect.Float32:
		if f.Remaining() < 4 {
			return 0
		}
		bits = uint64(f.fzgoSrc.Byte()) |
			uint64(f.fzgoSrc.Byte())<<8 |
			uint64(f.fzgoSrc.Byte())<<16 |
			uint64(f.fzgoSrc.Byte())<<24
	case reflect.Int16, reflect.Uint16:
		if f.Remaining() < 2 {
			return 0
		}
		bits = uint64(f.fzgoSrc.Byte()) |
			uint64(f.fzgoSrc.Byte())<<8
	case reflect.Int8, reflect.Uint8:
		if f.Remaining() < 1 {
			return 0
		}
		bits = uint64(f.fzgoSrc.Byte())
	default:
		panic(fmt.Sprintf("fzgen: numericDraw: unexpected kind %v", k))
	}
	return bits
}

// ---- TODO: TEMP compound types ----

func (f *Fuzzer) randByteArray4(val *[4]byte) {
	if f.fzgoSrc.Remaining() < len(val) {
		for _, i := range val {
			val[i] = 0
			return
		}
	}

	for i := 0; i < len(val); i++ {
		val[i] = f.fzgoSrc.Byte()
	}
}

func (f *Fuzzer) randByteArray8(val *[8]byte) {
	if f.fzgoSrc.Remaining() < len(val) {
		for _, i := range val {
			val[i] = 0
			return
		}
	}

	for i := 0; i < len(val); i++ {
		val[i] = f.fzgoSrc.Byte()
	}
}

func (f *Fuzzer) randByteArray16(val *[16]byte) {
	if f.fzgoSrc.Remaining() < len(val) {
		for _, i := range val {
			val[i] = 0
			return
		}
	}

	for i := 0; i < len(val); i++ {
		val[i] = f.fzgoSrc.Byte()
	}
}

func (f *Fuzzer) randByteArray20(val *[20]byte) {
	if f.fzgoSrc.Remaining() < len(val) {
		for _, i := range val {
			val[i] = 0
			return
		}
	}

	for i := 0; i < len(val); i++ {
		val[i] = f.fzgoSrc.Byte()
	}
}

func (f *Fuzzer) randByteArray32(val *[32]byte) {
	if f.fzgoSrc.Remaining() < len(val) {
		for _, i := range val {
			val[i] = 0
			return
		}
	}

	for i := 0; i < len(val); i++ {
		val[i] = f.fzgoSrc.Byte()
	}
}

// TODO: delete older comments here.
//
// ---- Basic types ----
// A set of custom numeric value filling funcs follows.
// These are currently simple implementations. When they used gofuzz.Continue
// as a source for data, it meant obtaining 64-bits of the input stream
// at a time. For sizes < 64 bits, this could be tighted up to waste less of the input stream
// by getting access to fzgo/randparam.randSource.
//
// Once the end of the input []byte is reached, zeros are drawn, including
// if in the middle of obtaining bytes for a >1 bye number.
// Tt is probably ok to draw zeros past the end
// for numbers because we use a little endian interpretation
// for numbers (which means if we find byte 0x1 then that's the end
// and we draw zeros for say a uint32, the result is 1; sonar
// seems to guess the length of numeric values, so it likely
// works end to end even if we draw zeros.
// TODO: The next bytes appended (via some mutation) after a number can change
// the result (e.g., if a 0x2 is appended in example above, result is no longer 1),
// so maybe better to also not draw zeros for numeric values?
