package store

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
)

// KeyStore is an interface type declaring
// functions for working with the keys
type KeyStore interface {
	SaveKey(ctx context.Context, keyID string, key []byte) error
	GetKey(ctx context.Context, keyID string) ([]byte, error)
	ListKeys(ctx context.Context) ([]string, error)
}

// memoryStore is type implementing KeyStore interface
// storing the keys data in memory
type memoryStore struct {
	keys  map[string][]byte
	mutex sync.RWMutex
}

func NewMemoryStore() KeyStore {
	ms := memoryStore{
		keys: make(map[string][]byte),
	}
	return &ms
}

// SaveKey saves a new key with provide keyID. Returns error
// when the key ID already exists or when the context was canceled or deadline
// passed.
func (m *memoryStore) SaveKey(ctx context.Context, keyID string, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()
	if _, ok := m.keys[keyID]; ok {
		return fmt.Errorf("Key ID %s already exists!", keyID)
	}
	m.keys[keyID] = bytes.Clone(key)
	return nil
}

// GetKey gets the key data for the corresponding key ID. Returns
// error when the key ID does not exist or when the context was canceled or deadline
// passed.
func (m *memoryStore) GetKey(ctx context.Context, keyID string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mutex.RLock()
	defer m.mutex.RUnlock()
	d, ok := m.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("key ID %s does not exist", keyID)
	}
	return bytes.Clone(d), nil
}

// ListKeys lists all the keys from the keys map. Returns error
// when the context was canceled or deadline passed.
func (m *memoryStore) ListKeys(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return slices.Collect(maps.Keys(m.keys)), nil
}
