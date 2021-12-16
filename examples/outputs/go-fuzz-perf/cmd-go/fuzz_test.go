package fuzzperf

import (
	"encoding/binary"
	"testing"
)

func findInt(i int) {
	if 1337 == i {
		panic("Found int")
	}
}

// FuzzIntegerLittleEndian shows how sonar can discover integers to use as inputs to increase coverage
func FuzzIntegerLittleEndian(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
        // interpret data as little-endian encoded
	if len(data) < 8 {
		return
	}
	findInt(int(binary.LittleEndian.Uint64(data)))
        })

}
