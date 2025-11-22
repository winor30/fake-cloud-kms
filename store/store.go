package store

import (
	"context"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/winor30/fake-cloud-kms/kmscrypto"
)

// Store defines persistence operations for key resources.
type Store interface {
	CreateKeyRing(ctx context.Context, keyRing *kmspb.KeyRing) error
	GetKeyRing(ctx context.Context, name string) (*kmspb.KeyRing, error)
	ListKeyRings(ctx context.Context, parent string) ([]*kmspb.KeyRing, error)

	CreateCryptoKey(ctx context.Context, keyRingName string, cryptoKey *kmspb.CryptoKey, primaryVersion *kmspb.CryptoKeyVersion, keyMaterial kmscrypto.KeyMaterial) error
	GetCryptoKey(ctx context.Context, name string) (*kmspb.CryptoKey, error)
	ListCryptoKeys(ctx context.Context, parent string) ([]*kmspb.CryptoKey, error)

	CreateCryptoKeyVersion(ctx context.Context, cryptoKeyName string, version *kmspb.CryptoKeyVersion, keyMaterial kmscrypto.KeyMaterial) error
	GetCryptoKeyVersion(ctx context.Context, name string) (*kmspb.CryptoKeyVersion, kmscrypto.KeyMaterial, error)
	ListCryptoKeyVersions(ctx context.Context, parent string) ([]*kmspb.CryptoKeyVersion, error)

	SetPrimaryVersion(ctx context.Context, cryptoKeyName, versionName string) (*kmspb.CryptoKey, error)
}

type StoreType string

const (
	StoreTypeMemory StoreType = "memory"
)
