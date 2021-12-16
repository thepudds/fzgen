// xsyncqueue is a thin wrapper over github.com/puzpuzpuz/xsync.MPMCQueue.

package xsyncqueue

import "github.com/puzpuzpuz/xsync"

type XSyncMPMCQueue struct {
	xsyncq *xsync.MPMCQueue
}

func NewMPMCQueue(capacity int) *XSyncMPMCQueue {
	return &XSyncMPMCQueue{xsync.NewMPMCQueue(capacity)}
}

func (q *XSyncMPMCQueue) Dequeue() int8 {
	return q.xsyncq.Dequeue().(int8)
}

func (q *XSyncMPMCQueue) Enqueue(item int8) {
	q.xsyncq.Enqueue(item)
}

func (q *XSyncMPMCQueue) TryDequeue() (item int8, ok bool) {
	v, ok := q.xsyncq.TryDequeue()
	if !ok {
		return 0, false
	}
	return v.(int8), true
}

func (q *XSyncMPMCQueue) TryEnqueue(item int8) bool {
	return q.xsyncq.TryEnqueue(item)
}
