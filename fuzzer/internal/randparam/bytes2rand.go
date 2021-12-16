package randparam

import (
	"encoding/binary"
)

// randSource supplies a stream of data via the rand.Source64 interface,
// but does so using an input data []byte. If randSource exhausts the
// data []byte, it start returning zeros.
type randSource struct {
	data []byte // data is the remaining byte stream to use for random values.
}

// Remaining reports how many bytes remain in our original input []byte.
func (s *randSource) Remaining() int {
	return len(s.data)
}

// Drain removes the next n bytes from the input []byte.
// If n is greater than Remaining, it drains all remaining bytes.
func (s *randSource) Drain(n int) {
	if len(s.data) >= n {
		s.data = s.data[n:]
	} else {
		s.data = nil
	}
}

// Data returns a []byte covering the remaining bytes from
// the original input []byte. Any bytes that are considered
// consumed should be indicated via Drain.
func (s *randSource) Data() []byte {
	return s.data
}

// PeekByte looks at the next byte without consuming it,
// also reporting whether it is an actual byte vs. a zero due to running out of bytes.
// TODO: remove? No longer using.
func (s *randSource) PeekByte() (byte, bool) {
	if len(s.data) > 0 {
		return s.data[0], true
	}
	return 0, false
}

func (s *randSource) Uint64() uint64 {
	if len(s.data) >= 8 {
		valBytes := s.data[:8]
		s.data = s.data[8:]
		return binary.LittleEndian.Uint64(valBytes)
	} else if len(s.data) > 0 {
		grab := len(s.data) // will be < 8
		valBytes := s.data[:grab]
		s.data = s.data[grab:]
		var val uint64
		for i, b := range valBytes {
			val |= uint64(b) << uint64(i*8)
		}
		return val
	}

	// we are out of bytes in our input stream.
	// fall back to zero.
	return 0
}

// Byte returns one byte, consuming only one byte of our input data.
// This is not part of rand.Source64 interface, but useful
// in our custom fuzzing functions so that we don't waste input
// bytes in the data []byte we receive from go-fuzz.
func (s *randSource) Byte() byte {
	if len(s.data) > 0 {
		val := s.data[0]
		s.data = s.data[1:]
		return val
	}
	// we are out of bytes in our input stream.
	// fall back to zero.
	return 0
}

// Int63 is needed for rand.Source64 interface.
func (s *randSource) Int63() int64 {
	return int64(s.Uint64() & ^uint64(1<<63))
}

// Seed is needed for rand.Source64 interface.
// It is a no-op for this package.
func (s *randSource) Seed(seed int64) {
	// no-op
}
