package fuzzwrapexamples

import (
	"context"
	"io"
	"net"
	"unsafe"
)

// ---- Various types examples/tests ----

// This should not trigger a fz.Fill and should not be skipped.
func Short1(x1 int) {}

// These should trigger a fz.Fill and should not be skipped.
func Short2(x1 *int)           {}
func Short3(x1 **int)          {}
func Short4(x1 MyInt)          {}
func Short5(x1 complex64)      {}
func Short6(x1 complex128)     {}
func Short7(x1 uintptr)        {}
func Short8(x1 unsafe.Pointer) {}

// This checks each of the major approaches for interfaces in the randparam.SupportedInterfaces map.
func InterfacesShortList(ctx context.Context, w io.Writer, r io.Reader, sw io.StringWriter, rc io.ReadCloser) {
	ctx.Err()
	io.Copy(w, r)
	sw.WriteString("hello")
	rc.Close()
}

// This is the full list from randparam.SupportedInterfaces.
func InterfacesFullList(
	x1 io.Writer,
	x2 io.Reader,
	x3 io.ReaderAt,
	x4 io.WriterTo,
	x5 io.Seeker,
	x6 io.ByteScanner,
	x7 io.RuneScanner,
	x8 io.ReadSeeker,
	x9 io.ByteReader,
	x10 io.RuneReader,
	x11 io.ByteWriter,
	x12 io.ReadWriter,
	x13 io.ReaderFrom,
	x14 io.StringWriter,
	x15 io.Closer,
	x16 io.ReadCloser,
	x17 context.Context) {
}

// This should be skipped due to unsupported interface.
func InterfacesSkip(c net.Conn) {}

type MyInt int
type MyStruct struct{ A int }

// This should trigger a fz.Fill and should not be skipped.
func TypesShortListFill(
	x1 int,
	x2 *int,
	x3 **int,
	x4 map[string]string,
	x5 *map[string]string,
	x6 MyInt,
	x7 [4]int,
	x8 MyStruct,
	x9 io.ByteReader,
	x10 io.RuneReader,
	x11 io.ByteWriter,
	x12 io.ReadWriter,
	x13 io.ReaderFrom,
	x14 io.StringWriter,
	x15 io.Closer,
	x16 io.ReadCloser,
	x17 context.Context) {
}

// This should not trigger a fz.Fill and should not be skipped.
func TypesShortListNoFill(
	x1 int,
	x5 string) {
}

// These should be skipped.
func TypesShortListSkip1(x chan bool) {}
func TypesShortListSkip2(x func(int)) {}

// This should triggier a fz.Fill with nil checks for non-chained output,
// and fz.Fill without nil checks for chained output.
type TypesNilCheck struct{}

func NewTypesNilCheck() *TypesNilCheck { return &TypesNilCheck{} }

func (n *TypesNilCheck) Pointers(
	x1 *int,
	x2 **int) {
}

func (n *TypesNilCheck) Interface(
	x1 io.Writer,
) {
}

func (n *TypesNilCheck) WriteTo(stream io.Writer) (int64, error) {
	return 0, nil
}

// Discard is modeled on tailscale.com/types/logger.Discard
func Discard(string, ...interface{}) {}

func Discard2(string, ...int) {}

// ListenPacket does not have a named receiver, and is modeled on tailscale.com/types/nettype
type Std struct{}

func (Std) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return nil, nil
}
