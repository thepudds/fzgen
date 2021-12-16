package xsyncmapfuzz

// repro extracted from:
//     fzgen -chain -parallel -pkg=github.com/thepudds/fzgen/examples/inputs/race-xsyncmap

import (
	"testing"

	xsyncqueue "github.com/thepudds/fzgen/examples/inputs/race-xsync-mpmcqueue"
)

func TestRepro_NewMPMCQueue_Chain(t *testing.T) {

	target := xsyncqueue.NewMPMCQueue(1)

	Fuzz_XSyncMPMCQueue_TryEnqueue := func(item int8) bool {
		return target.TryEnqueue(item)
	}
	Fuzz_XSyncMPMCQueue_Enqueue_Dequeue := func(item int8) int8 {
		target.Enqueue(item)
		return target.Dequeue()
	}

	Fuzz_XSyncMPMCQueue_TryEnqueue(0)
	Fuzz_XSyncMPMCQueue_Enqueue_Dequeue(0)
}
