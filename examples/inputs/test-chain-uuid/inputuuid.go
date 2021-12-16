// This is rougly modeled on a few examples from github.com/google/uuid.UUID.
// This is used for some basic tests.
package uuid

type MyUUID struct{}

// NewFromBytes should be picked up as the constructor by default via 'fzgen -chain'.
func NewFromBytes(b []byte) (uuid MyUUID, err error) { return MyUUID{}, nil }

// SetNodeID is a package-level func, and by default should NOT be included via 'fzgen -chain'.
// Currently fails (is included)
func SetNodeID(id []byte) bool { return false }

// URN has a non-pointer receiver, and by default SHOULD be included via 'fzgen -chain'.
// Currently fails (is missing)
func (uuid MyUUID) URN() string { return "" }

// UnmarshalBinary has a pointer receiver, and by default SHOULD be included via 'fzgen -chain'.
// Currently is correctly included.
// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (uuid *MyUUID) UnmarshalBinary(data []byte) error { return nil }

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (uuid MyUUID) MarshalBinary() ([]byte, error) { return nil, nil }
