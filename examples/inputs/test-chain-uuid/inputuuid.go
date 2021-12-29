// Package uuid is a simplified example for testing, roughly modeled on github.com/google/uuid.UUID.
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

// MyUUID2 is a second type that should also be picked up via 'fzgen -chain'.
type MyUUID2 struct{}

// This constructor returns a pointer, in constrast to NewFromBytes above.
func NewMyUUID2() *MyUUID2 { return &MyUUID2{} }

func (nu MyUUID2) Foo() ([]byte, error) { return nil, nil }

func (nu *MyUUID2) Bar(data []byte) error { return nil }

// This is not a constructor because string is not a named type.
func NewMyUUID3() string { return "" }

// MyUUID4 should not be picked up via 'fzgen -chain' because there is no constructor.
type MyUUID4 struct{}

func (u MyUUID4) Foo() ([]byte, error) { return nil, nil }
