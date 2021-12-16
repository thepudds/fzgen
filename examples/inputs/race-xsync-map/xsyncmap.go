// xsyncmap is a thin wrapper over github.com/puzpuzpuz/xsync.Map.

package xsyncmap

import "github.com/puzpuzpuz/xsync"

// target https://github.com/puzpuzpuz/xsync at 32778049b

type XSyncMap struct {
	xsyncmap *xsync.Map
}

func NewXSyncMap() *XSyncMap {
	return &XSyncMap{xsync.NewMap()}
}

func (m *XSyncMap) Delete(key string) {
	m.xsyncmap.Delete(key)
}

func (m *XSyncMap) Load(key string) (value int8, ok bool) {
	v, ok := m.xsyncmap.Load(key)
	if !ok {
		return 0, false
	}
	return v.(int8), ok
}

func (m *XSyncMap) LoadAndDelete(key string) (value int8, loaded bool) {
	v, loaded := m.xsyncmap.LoadAndDelete(key)
	if !loaded {
		return 0, false
	}
	return v.(int8), loaded
}

func (m *XSyncMap) LoadOrStore(key string, value int8) (actual int8, loaded bool) {
	v, loaded := m.xsyncmap.LoadOrStore(key, value)
	if !loaded {
		return 0, false
	}
	return v.(int8), loaded
}

func (m *XSyncMap) Store(key string, value int8) {
	m.xsyncmap.Store(key, value)
}

// Range will be ignored by default by fzgen.
func (m *XSyncMap) Range(f func(key string, value interface{}) bool) {
	m.xsyncmap.Range(f)
}
