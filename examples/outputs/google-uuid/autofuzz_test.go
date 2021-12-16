package uuidfuzz // rename if needed

// if needed, fill in imports or run 'goimports'
import (
	"io"
	"testing"

	"github.com/google/uuid"
	"github.com/thepudds/fzgen/fuzzer"
)

// skipping Fuzz_NullUUID_Scan because parameters include unsupported interface: interface{}

func Fuzz_NullUUID_UnmarshalBinary(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var nu *uuid.NullUUID
		var d2 []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&nu, &d2)
		if nu == nil {
			return
		}

		nu.UnmarshalBinary(d2)
	})
}

func Fuzz_NullUUID_UnmarshalJSON(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var nu *uuid.NullUUID
		var d2 []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&nu, &d2)
		if nu == nil {
			return
		}

		nu.UnmarshalJSON(d2)
	})
}

func Fuzz_NullUUID_UnmarshalText(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var nu *uuid.NullUUID
		var d2 []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&nu, &d2)
		if nu == nil {
			return
		}

		nu.UnmarshalText(d2)
	})
}

// skipping Fuzz_UUID_Scan because parameters include unsupported interface: interface{}

func Fuzz_UUID_UnmarshalBinary(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte, d2 []byte) {
		u1, err := uuid.FromBytes(b)
		if err != nil {
			return
		}
		u1.UnmarshalBinary(d2)
	})
}

func Fuzz_UUID_UnmarshalText(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte, d2 []byte) {
		u1, err := uuid.FromBytes(b)
		if err != nil {
			return
		}
		u1.UnmarshalText(d2)
	})
}

func Fuzz_Domain_String(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var d uuid.Domain
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&d)

		d.String()
	})
}

func Fuzz_NullUUID_MarshalBinary(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var nu uuid.NullUUID
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&nu)

		nu.MarshalBinary()
	})
}

func Fuzz_NullUUID_MarshalJSON(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var nu uuid.NullUUID
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&nu)

		nu.MarshalJSON()
	})
}

func Fuzz_NullUUID_MarshalText(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var nu uuid.NullUUID
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&nu)

		nu.MarshalText()
	})
}

func Fuzz_NullUUID_Value(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var nu uuid.NullUUID
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&nu)

		nu.Value()
	})
}

func Fuzz_Time_UnixTime(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var t1 uuid.Time
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&t1)

		t1.UnixTime()
	})
}

func Fuzz_UUID_ClockSequence(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		u1, err := uuid.FromBytes(b)
		if err != nil {
			return
		}
		u1.ClockSequence()
	})
}

func Fuzz_UUID_Domain(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		u1, err := uuid.FromBytes(b)
		if err != nil {
			return
		}
		u1.Domain()
	})
}

func Fuzz_UUID_ID(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		u1, err := uuid.FromBytes(b)
		if err != nil {
			return
		}
		u1.ID()
	})
}

func Fuzz_UUID_MarshalBinary(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		u1, err := uuid.FromBytes(b)
		if err != nil {
			return
		}
		u1.MarshalBinary()
	})
}

func Fuzz_UUID_MarshalText(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		u1, err := uuid.FromBytes(b)
		if err != nil {
			return
		}
		u1.MarshalText()
	})
}

func Fuzz_UUID_NodeID(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		u1, err := uuid.FromBytes(b)
		if err != nil {
			return
		}
		u1.NodeID()
	})
}

func Fuzz_UUID_String(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		u1, err := uuid.FromBytes(b)
		if err != nil {
			return
		}
		u1.String()
	})
}

func Fuzz_UUID_Time(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		u1, err := uuid.FromBytes(b)
		if err != nil {
			return
		}
		u1.Time()
	})
}

func Fuzz_UUID_URN(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		u1, err := uuid.FromBytes(b)
		if err != nil {
			return
		}
		u1.URN()
	})
}

func Fuzz_UUID_Value(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		u1, err := uuid.FromBytes(b)
		if err != nil {
			return
		}
		u1.Value()
	})
}

func Fuzz_UUID_Variant(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		u1, err := uuid.FromBytes(b)
		if err != nil {
			return
		}
		u1.Variant()
	})
}

func Fuzz_UUID_Version(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		u1, err := uuid.FromBytes(b)
		if err != nil {
			return
		}
		u1.Version()
	})
}

func Fuzz_Variant_String(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var v uuid.Variant
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&v)

		v.String()
	})
}

func Fuzz_Version_String(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var v uuid.Version
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&v)

		v.String()
	})
}

func Fuzz_FromBytes(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		uuid.FromBytes(b)
	})
}

// skipping Fuzz_IsInvalidLengthError because parameters include unsupported interface: error

// skipping Fuzz_Must because parameters include unsupported interface: error

func Fuzz_MustParse(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		uuid.MustParse(s)
	})
}

func Fuzz_NewDCESecurity(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var domain uuid.Domain
		var id uint32
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&domain, &id)

		uuid.NewDCESecurity(domain, id)
	})
}

// skipping Fuzz_NewHash because parameters include unsupported interface: hash.Hash

func Fuzz_NewMD5(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var space uuid.UUID
		var d2 []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&space, &d2)

		uuid.NewMD5(space, d2)
	})
}

func Fuzz_NewRandomFromReader(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var r io.Reader
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&r)

		uuid.NewRandomFromReader(r)
	})
}

func Fuzz_NewSHA1(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var space uuid.UUID
		var d2 []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&space, &d2)

		uuid.NewSHA1(space, d2)
	})
}

func Fuzz_Parse(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		uuid.Parse(s)
	})
}

func Fuzz_ParseBytes(f *testing.F) {
	f.Fuzz(func(t *testing.T, b []byte) {
		uuid.ParseBytes(b)
	})
}

func Fuzz_SetClockSequence(f *testing.F) {
	f.Fuzz(func(t *testing.T, seq int) {
		uuid.SetClockSequence(seq)
	})
}

func Fuzz_SetNodeID(f *testing.F) {
	f.Fuzz(func(t *testing.T, id []byte) {
		uuid.SetNodeID(id)
	})
}

func Fuzz_SetNodeInterface(f *testing.F) {
	f.Fuzz(func(t *testing.T, name string) {
		uuid.SetNodeInterface(name)
	})
}

func Fuzz_SetRand(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var r io.Reader
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&r)

		uuid.SetRand(r)
	})
}
