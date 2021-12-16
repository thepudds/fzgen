// raceexample wraps sync.Map in a type-safe way, but sadly the implementation has a
// a possible data race in handling a counter on the objects stored in the sync.Map.
//
// To observe the data race with the race detector:
//     1. A Store must be followed by two Loads, and all three must use the same key.
//     2. The Store must have certain payload data (Answer: 42).
//     3. The two Loads must happen concurrently.
//     4. Prior to the two Loads, no other Store can update the key to have a non-matching payload.
//
// Using the fzgen/fuzzer.Chain created by default via 'fzgen -chain -parallel github.com/thepudds/fzgen/examples/inputs/race',
// this data race is typically caught after a few minutes of fuzzing with '-race' when starting from scratch.
package raceexample

import (
	"sync"
)

type MySafeMap struct {
	syncMap sync.Map
}

func NewMySafeMap() *MySafeMap {
	return &MySafeMap{}
}

func (m *MySafeMap) Store(key [16]byte, req *Request) {
	m.syncMap.Store(key, req)
}

func (m *MySafeMap) Load(key [16]byte) *Request {
	r, ok := m.syncMap.Load(key)
	if ok {
		req := r.(*Request)
		if req.Answer == 42 {
			// DATA RACE (but detection requires: matching store/load keys, and concurrent matching load keys, and certain payload data)
			req.deepQuestion++
		}
		return req
	}
	return nil
}

type Request struct {
	Answer       int8 // TODO: change to int when cmd/go has the equivalent of go-fuzz sonar or libfuzzer comparision instrumentation
	deepQuestion int
}
