package uuidfuzz

import (
	"database/sql/driver"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/thepudds/fzgen/fuzzer"
)

// Automatically generated via:
//      fzgen -chain -ctor=FromBytes github.com/google/uuid

func Fuzz_FromBytes_Chain(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		var b []byte
		fz := fuzzer.NewFuzzer(data)
		fz.Fill(&b)

		target, err := uuid.FromBytes(b)
		if err != nil {
			return
		}

		steps := []fuzzer.Step{
			// skipping Fuzz_UUID_Scan because parameters include unsupported interface: interface{}
			{
				Name: "Fuzz_UUID_UnmarshalBinary",
				Func: func(d1 []byte) {
					target.UnmarshalBinary(d1)
				},
			},
			{
				Name: "Fuzz_UUID_UnmarshalText",
				Func: func(d1 []byte) {
					target.UnmarshalText(d1)
				},
			},
			{
				Name: "Fuzz_UUID_ClockSequence",
				Func: func() int {
					return target.ClockSequence()
				},
			},
			{
				Name: "Fuzz_UUID_Domain",
				Func: func() uuid.Domain {
					return target.Domain()
				},
			},
			{
				Name: "Fuzz_UUID_ID",
				Func: func() uint32 {
					return target.ID()
				},
			},
			{
				Name: "Fuzz_UUID_MarshalBinary",
				Func: func() ([]byte, error) {
					return target.MarshalBinary()
				},
			},
			{
				Name: "Fuzz_UUID_MarshalText",
				Func: func() ([]byte, error) {
					return target.MarshalText()
				},
			},
			{
				Name: "Fuzz_UUID_NodeID",
				Func: func() []byte {
					return target.NodeID()
				},
			},
			{
				Name: "Fuzz_UUID_String",
				Func: func() string {
					return target.String()
				},
			},
			{
				Name: "Fuzz_UUID_Time",
				Func: func() uuid.Time {
					return target.Time()
				},
			},
			{
				Name: "Fuzz_UUID_URN",
				Func: func() string {
					return target.URN()
				},
			},
			{
				Name: "Fuzz_UUID_Value",
				Func: func() (driver.Value, error) {
					return target.Value()
				},
			},
			{
				Name: "Fuzz_UUID_Variant",
				Func: func() uuid.Variant {
					return target.Variant()
				},
			},
			{
				Name: "Fuzz_UUID_Version",
				Func: func() uuid.Version {
					return target.Version()
				},
			},
		}

		// Execute a specific chain of steps, with the count, sequence and arguments controlled by fz.Chain
		fz.Chain(steps)

		// Validate with some roundtrip checks. These can be edited or deleted if not appropriate for your target.
		// Check MarshalText.
		result1, err := target.MarshalText()
		if err != nil {
			// Some targets should never return an error here for an object created by a constructor.
			// If that is the case for your target, you can change this to a panic(err) or t.Fatal.
			return
		}

		// Check UnmarshalText.
		var tmp1 uuid.UUID
		err = tmp1.UnmarshalText(result1)
		if err != nil {
			panic(fmt.Sprintf("UnmarshalText failed after successful MarshalText. original: %v marshalled: %q error: %v", target, result1, err))
		}
		if !reflect.DeepEqual(target, tmp1) {
			panic(fmt.Sprintf("MarshalText/UnmarshalText roundtrip equality failed. original: %v  marshalled: %q unmarshalled: %v", target, result1, tmp1))
		}

		// Check MarshalBinary.
		result2, err := target.MarshalBinary()
		if err != nil {
			// Some targets should never return an error here for an object created by a constructor.
			// If that is the case for your target, you can change this to a panic(err) or t.Fatal.
			return
		}

		// Check UnmarshalBinary.
		var tmp2 uuid.UUID
		err = tmp2.UnmarshalBinary(result2)
		if err != nil {
			panic(fmt.Sprintf("UnmarshalBinary failed after successful MarshalBinary. original: %v %#v marshalled: %q error: %v", target, target, result2, err))
		}
		if !reflect.DeepEqual(target, tmp2) {
			panic(fmt.Sprintf("MarshalBinary/UnmarshalBinary roundtrip equality failed. original: %v %#v marshalled: %q unmarshalled: %v %#v",
				target, target, result2, tmp2, tmp2))
		}
	})
}
