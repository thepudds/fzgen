package uuidfuzz

import "github.com/google/uuid"

// Automatically generated via:
//    genfuzzfuncs -pkg=github.com/google/uuid > uuid_fuzz.go
//    goimports -w uuid_fuzz.go
// You can then fuzz these rich signatures via:
//    fzgo test -fuzz=.

func Fuzz_UUID_MarshalBinary(u1 uuid.UUID) {
	u1.MarshalBinary()
}

func Fuzz_UUID_MarshalText(u1 uuid.UUID) {
	u1.MarshalText()
}

func Fuzz_UUID_UnmarshalBinary(u1 *uuid.UUID, data []byte) {
	if u1 == nil {
		return
	}
	u1.UnmarshalBinary(data)
}

func Fuzz_UUID_UnmarshalText(u1 *uuid.UUID, data []byte) {
	if u1 == nil {
		return
	}
	u1.UnmarshalText(data)
}

// skipping Fuzz_UUID_Scan because parameters include interfaces or funcs: interface{}

func Fuzz_Time_UnixTime(t uuid.Time) {
	t.UnixTime()
}

func Fuzz_UUID_ClockSequence(u1 uuid.UUID) {
	u1.ClockSequence()
}

func Fuzz_UUID_Domain(u1 uuid.UUID) {
	u1.Domain()
}

func Fuzz_UUID_ID(u1 uuid.UUID) {
	u1.ID()
}

func Fuzz_UUID_NodeID(u1 uuid.UUID) {
	u1.NodeID()
}

func Fuzz_Domain_String(d uuid.Domain) {
	d.String()
}

func Fuzz_UUID_String(u1 uuid.UUID) {
	u1.String()
}

func Fuzz_UUID_Time(u1 uuid.UUID) {
	u1.Time()
}

func Fuzz_UUID_URN(u1 uuid.UUID) {
	u1.URN()
}

func Fuzz_UUID_Value(u1 uuid.UUID) {
	u1.Value()
}

func Fuzz_UUID_Variant(u1 uuid.UUID) {
	u1.Variant()
}

func Fuzz_UUID_Version(u1 uuid.UUID) {
	u1.Version()
}

func Fuzz_Variant_String(v uuid.Variant) {
	v.String()
}

func Fuzz_Version_String(v uuid.Version) {
	v.String()
}

func Fuzz_FromBytes(b []byte) {
	uuid.FromBytes(b)
}

// skipping Fuzz_Must because parameters include interfaces or funcs: error

func Fuzz_MustParse(s string) {
	uuid.MustParse(s)
}

func Fuzz_NewDCESecurity(domain uuid.Domain, id uint32) {
	uuid.NewDCESecurity(domain, id)
}

// skipping Fuzz_NewHash because parameters include interfaces or funcs: hash.Hash

func Fuzz_NewMD5(space uuid.UUID, data []byte) {
	uuid.NewMD5(space, data)
}

// skipping Fuzz_NewRandomFromReader because parameters include interfaces or funcs: io.Reader

func Fuzz_NewSHA1(space uuid.UUID, data []byte) {
	uuid.NewSHA1(space, data)
}

func Fuzz_Parse(s string) {
	uuid.Parse(s)
}

func Fuzz_ParseBytes(b []byte) {
	uuid.ParseBytes(b)
}

func Fuzz_SetClockSequence(seq int) {
	uuid.SetClockSequence(seq)
}

func Fuzz_SetNodeID(id []byte) {
	uuid.SetNodeID(id)
}

func Fuzz_SetNodeInterface(name string) {
	uuid.SetNodeInterface(name)
}

// skipping Fuzz_SetRand because parameters include interfaces or funcs: io.Reader
