package memory

import (
	"context"
	"maps"
	"slices"
	"sync"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/winor30/fake-cloud-kms/kmscrypto"
	"github.com/winor30/fake-cloud-kms/names"
	"github.com/winor30/fake-cloud-kms/store"
)

// Store implements an in-memory storage backend.
type Store struct {
	mu       sync.RWMutex
	keyRings map[string]*keyRingRecord
}

var _ store.Store = (*Store)(nil)

// New creates a new in-memory store instance.
func New() *Store {
	return &Store{keyRings: make(map[string]*keyRingRecord)}
}

type keyRingRecord struct {
	keyRing    *kmspb.KeyRing
	cryptoKeys map[string]*cryptoKeyRecord
}

type cryptoKeyRecord struct {
	cryptoKey *kmspb.CryptoKey
	versions  map[string]*cryptoKeyVersionRecord
}

type cryptoKeyVersionRecord struct {
	version     *kmspb.CryptoKeyVersion
	keyMaterial kmscrypto.KeyMaterial
}

func cloneKeyRing(in *kmspb.KeyRing) *kmspb.KeyRing {
	return proto.Clone(in).(*kmspb.KeyRing)
}

func cloneCryptoKey(in *kmspb.CryptoKey) *kmspb.CryptoKey {
	return proto.Clone(in).(*kmspb.CryptoKey)
}

func cloneCryptoKeyVersion(in *kmspb.CryptoKeyVersion) *kmspb.CryptoKeyVersion {
	return proto.Clone(in).(*kmspb.CryptoKeyVersion)
}

// CreateKeyRing stores a new key ring.
func (s *Store) CreateKeyRing(_ context.Context, keyRing *kmspb.KeyRing) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.keyRings[keyRing.GetName()]; ok {
		return status.Errorf(codes.AlreadyExists, "key ring %q already exists", keyRing.GetName())
	}

	s.keyRings[keyRing.GetName()] = &keyRingRecord{
		keyRing:    cloneKeyRing(keyRing),
		cryptoKeys: make(map[string]*cryptoKeyRecord),
	}
	return nil
}

// GetKeyRing returns the stored key ring.
func (s *Store) GetKeyRing(_ context.Context, name string) (*kmspb.KeyRing, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.keyRings[name]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "key ring %q not found", name)
	}
	return cloneKeyRing(rec.keyRing), nil
}

// ListKeyRings lists key rings under the parent.
func (s *Store) ListKeyRings(_ context.Context, parent string) ([]*kmspb.KeyRing, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	namesInStore := slices.Sorted(maps.Keys(s.keyRings))
	rings := make([]*kmspb.KeyRing, 0, len(namesInStore))
	for _, name := range namesInStore {
		krName, err := names.ParseKeyRing(name)
		if err != nil || krName.ParentName() != parent {
			continue
		}
		rings = append(rings, cloneKeyRing(s.keyRings[name].keyRing))
	}
	return rings, nil
}

// CreateCryptoKey stores a crypto key and its initial primary version.
func (s *Store) CreateCryptoKey(_ context.Context, keyRingName string, cryptoKey *kmspb.CryptoKey, primaryVersion *kmspb.CryptoKeyVersion, keyMaterial kmscrypto.KeyMaterial) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ring, ok := s.keyRings[keyRingName]
	if !ok {
		return status.Errorf(codes.NotFound, "key ring %q not found", keyRingName)
	}

	if _, exists := ring.cryptoKeys[cryptoKey.GetName()]; exists {
		return status.Errorf(codes.AlreadyExists, "crypto key %q already exists", cryptoKey.GetName())
	}

	versionRecord := &cryptoKeyVersionRecord{
		version:     cloneCryptoKeyVersion(primaryVersion),
		keyMaterial: kmscrypto.KeyMaterial(slices.Clone(keyMaterial)),
	}

	rec := &cryptoKeyRecord{
		cryptoKey: cloneCryptoKey(cryptoKey),
		versions: map[string]*cryptoKeyVersionRecord{
			primaryVersion.GetName(): versionRecord,
		},
	}
	ring.cryptoKeys[cryptoKey.GetName()] = rec
	return nil
}

// GetCryptoKey returns the crypto key by name.

func (s *Store) GetCryptoKey(_ context.Context, name string) (*kmspb.CryptoKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	lookup, err := s.findCryptoKey(name)
	if err != nil {
		return nil, err
	}
	return cloneCryptoKey(lookup.key.cryptoKey), nil
}

// ListCryptoKeys lists keys under a key ring parent.
func (s *Store) ListCryptoKeys(_ context.Context, parent string) ([]*kmspb.CryptoKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ring, ok := s.keyRings[parent]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "key ring %q not found", parent)
	}

	keyNames := slices.Sorted(maps.Keys(ring.cryptoKeys))
	keys := make([]*kmspb.CryptoKey, 0, len(keyNames))
	for _, keyName := range keyNames {
		keys = append(keys, cloneCryptoKey(ring.cryptoKeys[keyName].cryptoKey))
	}
	return keys, nil
}

// CreateCryptoKeyVersion stores a new version for a crypto key.
func (s *Store) CreateCryptoKeyVersion(_ context.Context, cryptoKeyName string, version *kmspb.CryptoKeyVersion, keyMaterial kmscrypto.KeyMaterial) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	keyLookup, err := s.findCryptoKey(cryptoKeyName)
	if err != nil {
		return err
	}

	if _, exists := keyLookup.key.versions[version.GetName()]; exists {
		return status.Errorf(codes.AlreadyExists, "crypto key version %q already exists", version.GetName())
	}

	keyLookup.key.versions[version.GetName()] = &cryptoKeyVersionRecord{
		version:     cloneCryptoKeyVersion(version),
		keyMaterial: kmscrypto.KeyMaterial(slices.Clone(keyMaterial)),
	}
	return nil
}

// GetCryptoKeyVersion returns the version and its key material.

func (s *Store) GetCryptoKeyVersion(_ context.Context, name string) (*kmspb.CryptoKeyVersion, kmscrypto.KeyMaterial, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	lookup, err := s.findVersion(name)
	if err != nil {
		return nil, nil, err
	}

	return cloneCryptoKeyVersion(lookup.version.version), kmscrypto.KeyMaterial(slices.Clone(lookup.version.keyMaterial)), nil
}

// ListCryptoKeyVersions lists versions under parent.
func (s *Store) ListCryptoKeyVersions(_ context.Context, parent string) ([]*kmspb.CryptoKeyVersion, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keyLookup, err := s.findCryptoKey(parent)
	if err != nil {
		return nil, err
	}

	versionNames := slices.Sorted(maps.Keys(keyLookup.key.versions))
	versions := make([]*kmspb.CryptoKeyVersion, 0, len(versionNames))
	for _, name := range versionNames {
		versions = append(versions, cloneCryptoKeyVersion(keyLookup.key.versions[name].version))
	}
	return versions, nil
}

// SetPrimaryVersion updates the primary version pointer.
func (s *Store) SetPrimaryVersion(_ context.Context, cryptoKeyName, versionName string) (*kmspb.CryptoKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	lookup, err := s.findVersion(versionName)
	if err != nil {
		return nil, err
	}

	if lookup.key.cryptoKey.GetName() != cryptoKeyName {
		return nil, status.Errorf(codes.NotFound, "crypto key %q not found for version %q", cryptoKeyName, versionName)
	}

	lookup.key.cryptoKey.Primary = cloneCryptoKeyVersion(lookup.version.version)
	return cloneCryptoKey(lookup.key.cryptoKey), nil
}

type keyLookup struct {
	ring *keyRingRecord
	key  *cryptoKeyRecord
}

type versionLookup struct {
	ring    *keyRingRecord
	key     *cryptoKeyRecord
	version *cryptoKeyVersionRecord
}

func (s *Store) findCryptoKey(name string) (*keyLookup, error) {
	for _, ring := range s.keyRings {
		if rec, ok := ring.cryptoKeys[name]; ok {
			return &keyLookup{ring: ring, key: rec}, nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "crypto key %q not found", name)
}

func (s *Store) findVersion(name string) (*versionLookup, error) {
	for _, ring := range s.keyRings {
		for _, key := range ring.cryptoKeys {
			if ver, ok := key.versions[name]; ok {
				return &versionLookup{ring: ring, key: key, version: ver}, nil
			}
		}
	}
	return nil, status.Errorf(codes.NotFound, "crypto key version %q not found", name)
}
