package kmscrypto

import (
	"bytes"
	"context"

	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// KeyMaterial represents serialized key bytes produced by the engine.
type KeyMaterial []byte

// Engine defines encryption helpers for symmetric crypto key versions.
type Engine interface {
	GenerateKeyMaterial(ctx context.Context) (KeyMaterial, error)
	Encrypt(ctx context.Context, keyMaterial KeyMaterial, plaintext, associatedData []byte) ([]byte, error)
	Decrypt(ctx context.Context, keyMaterial KeyMaterial, ciphertext, associatedData []byte) ([]byte, error)
}

// TinkEngine implements Engine using tink-go AES256-GCM primitives.
type TinkEngine struct{}

var _ Engine = &TinkEngine{}

// NewTinkEngine creates a new engine instance.
func NewTinkEngine() *TinkEngine {
	return &TinkEngine{}
}

// GenerateKeyMaterial produces a serialized AES256-GCM keyset.
func (e *TinkEngine) GenerateKeyMaterial(ctx context.Context) (KeyMaterial, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	kh, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := insecurecleartextkeyset.Write(kh, keyset.NewBinaryWriter(&buf)); err != nil {
		return nil, err
	}
	return KeyMaterial(buf.Bytes()), nil
}

// Encrypt encrypts plaintext using the serialized key material.
func (e *TinkEngine) Encrypt(ctx context.Context, keyMaterial KeyMaterial, plaintext, associatedData []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	primitive, err := e.primitiveFromMaterial(keyMaterial)
	if err != nil {
		return nil, err
	}
	return primitive.Encrypt(plaintext, associatedData)
}

// Decrypt decrypts ciphertext using the serialized key material.
func (e *TinkEngine) Decrypt(ctx context.Context, keyMaterial KeyMaterial, ciphertext, associatedData []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	primitive, err := e.primitiveFromMaterial(keyMaterial)
	if err != nil {
		return nil, err
	}
	return primitive.Decrypt(ciphertext, associatedData)
}

func (e *TinkEngine) primitiveFromMaterial(material KeyMaterial) (tink.AEAD, error) {
	reader := bytes.NewReader(material)
	kh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(reader))
	if err != nil {
		return nil, err
	}
	return aead.New(kh)
}
