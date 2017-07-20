package nat

import (
	"net"
	"sync"
)

// IPMap represents a IP to IP map with RWMutex
type IPMap struct {
	s map[string]net.IP
	l *sync.RWMutex
}

// NewIPMap create a new IPMap
func NewIPMap() *IPMap {
	return &IPMap{
		s: make(map[string]net.IP),
		l: &sync.RWMutex{},
	}
}

// Set set k-v
func (m *IPMap) Set(k net.IP, v net.IP) {
	m.l.Lock()
	defer m.l.Unlock()
	m.s[k.String()] = v
}

// Get get k-v
func (m *IPMap) Get(k net.IP) net.IP {
	m.l.RLock()
	defer m.l.RUnlock()
	return m.s[k.String()]
}

// Delete delete a key
func (m *IPMap) Delete(k net.IP) {
	m.l.Lock()
	defer m.l.Unlock()
	delete(m.s, k.String())
}
