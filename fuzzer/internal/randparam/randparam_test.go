package randparam

import (
	"encoding/binary"
	"io"
	"io/ioutil"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestFuzzingBasicTypes(t *testing.T) {
	t.Run("string - 8 byte length, 8 bytes of string input", func(t *testing.T) {
		input := append([]byte{0x0, 0x8}, []byte("12345678")...)
		want := "12345678"

		fuzzer := NewFuzzer(input)
		var got string
		fuzzer.Fill2(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("string - 9 byte length, 9 bytes of string input", func(t *testing.T) {
		input := append([]byte{0x0, 0x9}, []byte("123456789")...)
		want := "123456789"

		fuzzer := NewFuzzer(input)
		var got string
		fuzzer.Fill2(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("string - 5 byte length, 6 bytes of string input", func(t *testing.T) {
		input := append([]byte{0x0, 0x5}, []byte("123456")...)
		want := "12345"

		fuzzer := NewFuzzer(input)
		var got string
		fuzzer.Fill2(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("string - 9 byte length, 2 bytes of string input", func(t *testing.T) {
		input := append([]byte{0x0, 0x9}, []byte("12")...)
		want := ""

		fuzzer := NewFuzzer(input)
		var got string
		fuzzer.Fill2(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("string - zero length string explicitly encoded", func(t *testing.T) {
		longByteSlice := make([]byte, 1000)
		input := append([]byte{0x0, 0xFF}, longByteSlice...)
		want := ""

		fuzzer := NewFuzzer(input)
		var got string
		fuzzer.Fill2(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("string - skip 0x0 size fields", func(t *testing.T) {
		input := append([]byte{0x0, 0x0, 0x2}, []byte("12")...)
		want := "12"

		fuzzer := NewFuzzer(input)
		var got string
		fuzzer.Fill2(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("string - two strings", func(t *testing.T) {
		input := []byte{0x0, 0x1, 0x42, 0x2, 0x43, 0x44}
		want1 := string([]byte{0x42})
		want2 := string([]byte{0x43, 0x44})

		fuzzer := NewFuzzer(input)
		var got1, got2 string
		fuzzer.Fill2(&got1)
		fuzzer.Fill2(&got2)

		if diff := cmp.Diff(want1, got1); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want1 +got1):\n%s", diff)
		}
		if diff := cmp.Diff(want2, got2); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want2 +got2):\n%s", diff)
		}
	})

	t.Run("string - exactly run out of bytes", func(t *testing.T) {
		input := []byte{0x0, 0x1, 0x42}
		want1 := string([]byte{0x42})
		want2 := ""

		fuzzer := NewFuzzer(input)
		var got1, got2 string
		fuzzer.Fill2(&got1)
		fuzzer.Fill2(&got2)

		if diff := cmp.Diff(want1, got1); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want1 +got1):\n%s", diff)
		}
		if diff := cmp.Diff(want2, got2); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want2 +got2):\n%s", diff)
		}
	})

	t.Run("byte slice - 8 byte length, 8 input bytes", func(t *testing.T) {
		input := append([]byte{0x0, 0x8}, []byte("12345678")...)
		want := []byte("12345678")

		fuzzer := NewFuzzer(input)
		var got []byte
		fuzzer.Fill2(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("byte slice - 3 byte length, 8 input bytes", func(t *testing.T) {
		input := append([]byte{0x0, 0x3}, []byte("12345678")...)
		want := []byte("123")

		fuzzer := NewFuzzer(input)
		var got []byte
		fuzzer.Fill2(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("bytes slice - 9 byte length, 2 bytes of string input", func(t *testing.T) {
		input := append([]byte{0x0, 0x9}, []byte("12")...)
		want := []byte{}

		fuzzer := NewFuzzer(input)
		var got []byte
		fuzzer.Fill2(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("uint64 - 8 bytes input", func(t *testing.T) {
		input := append([]byte{0x0}, make([]byte, 8)...)
		i := uint64(0xfeedfacedeadbeef)
		binary.LittleEndian.PutUint64(input[1:], i)
		want := uint64(0xfeedfacedeadbeef)

		fuzzer := NewFuzzer(input)
		var got uint64
		fuzzer.Fill2(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("uint64 - 4 bytes input", func(t *testing.T) {
		input := []byte{0x0, 0xef, 0xbe, 0xad, 0xde}
		want := uint64(0x0)

		fuzzer := NewFuzzer(input)
		var got uint64
		fuzzer.Fill2(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("int32 - 4 bytes input with zeros", func(t *testing.T) {
		input := []byte{0x0, 0x42, 0x00, 0x00, 0x00}
		want := int32(0x42)

		fuzzer := NewFuzzer(input)
		var got int32
		fuzzer.Fill2(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("int32 - 1 byte input", func(t *testing.T) {
		input := []byte{0x0, 0x42}
		want := int32(0x0)

		fuzzer := NewFuzzer(input)
		var got int32
		fuzzer.Fill2(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestFuzzingInterfaces(t *testing.T) {
	t.Run("io.Reader - 8 byte length, 8 bytes of string input", func(t *testing.T) {
		input := append([]byte{0x0, 0x8}, []byte("12345678")...)
		want := "12345678"

		fuzzer := NewFuzzer(input)
		var r io.Reader
		fuzzer.Fill2(&r)
		b, err := ioutil.ReadAll(r)
		if err != nil {
			t.Errorf("fuzzer.Fill() returned err: %v", err)
		}
		got := string(b)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("io.ReadWriter - 8 byte length, 8 bytes of string input", func(t *testing.T) {
		input := append([]byte{0x0, 0x8}, []byte("12345678")...)
		want := "12345678"

		fuzzer := NewFuzzer(input)
		var rw io.ReadWriter
		fuzzer.Fill2(&rw)
		b, err := ioutil.ReadAll(rw)
		if err != nil {
			t.Errorf("fuzzer.Fill() returned err: %v", err)
		}
		got := string(b)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("io.ReadCloser - 8 byte length, 8 bytes of string input", func(t *testing.T) {
		input := append([]byte{0x0, 0x8}, []byte("12345678")...)
		want := "12345678"

		fuzzer := NewFuzzer(input)
		var rc io.ReadCloser
		fuzzer.Fill2(&rc)
		b, err := ioutil.ReadAll(rc)
		if err != nil {
			t.Errorf("fuzzer.Fill() returned err: %v", err)
		}
		got := string(b)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestFuzzingStructs(t *testing.T) {
	t.Run("uint64 in struct - 8 bytes input", func(t *testing.T) {
		type Foo struct {
			U *uint64
		}
		input := append([]byte{0x0}, make([]byte, 8)...)
		i := uint64(0xfeedfacedeadbeef)
		binary.LittleEndian.PutUint64(input[1:], i)

		u := uint64(0xfeedfacedeadbeef)
		want := Foo{&u}

		fuzzer := NewFuzzer(input)
		var got Foo
		fuzzer.Fill2(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("uint32 slice in struct - 8 bytes input", func(t *testing.T) {
		input := append([]byte{0x0, 0x2}, make([]byte, 8)...)
		i1 := uint32(0xfeedface)
		i2 := uint32(0xdeadbeef)
		binary.LittleEndian.PutUint32(input[2:], i1)
		binary.LittleEndian.PutUint32(input[6:], i2)

		type Foo struct {
			U []uint32
		}
		want := Foo{[]uint32{0xfeedface, 0xdeadbeef}}

		fuzzer := NewFuzzer(input)
		var got Foo
		fuzzer.Fill2(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("map in struct - 8 bytes input", func(t *testing.T) {
		input := append([]byte{0x0, 0x1}, make([]byte, 8)...)
		i1 := uint32(0xfeedface)
		i2 := uint32(0xdeadbeef)
		binary.LittleEndian.PutUint32(input[2:], i1)
		binary.LittleEndian.PutUint32(input[6:], i2)

		type Foo struct {
			M map[uint32]uint32
		}
		want := Foo{
			M: map[uint32]uint32{0xfeedface: 0xdeadbeef},
		}

		fuzzer := NewFuzzer(input)
		var got Foo
		fuzzer.Fill2(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("uint32 array in struct - 8 bytes input", func(t *testing.T) {
		input := append([]byte{0x0}, make([]byte, 8)...)
		i1 := uint32(0xfeedface)
		i2 := uint32(0xdeadbeef)
		binary.LittleEndian.PutUint32(input[1:], i1)
		binary.LittleEndian.PutUint32(input[5:], i2)

		type Foo struct {
			U [2]uint32
		}
		want := Foo{[2]uint32{0xfeedface, 0xdeadbeef}}

		fuzzer := NewFuzzer(input)
		var got Foo
		fuzzer.Fill2(&got)
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("fuzzer.Fill() mismatch (-want +got):\n%s", diff)
		}
	})
}
