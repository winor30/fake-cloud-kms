package kmscrypto

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
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

	GenerateAsymmetricKeyMaterial(ctx context.Context, algorithm string) (KeyMaterial, error)
	Sign(ctx context.Context, keyMaterial KeyMaterial, digest []byte) ([]byte, error)
	GetPublicKeyPEM(ctx context.Context, keyMaterial KeyMaterial) ([]byte, error)
}

// TinkEngine implements Engine using tink-go AES256-GCM primitives
// and btcec for secp256k1 asymmetric operations.
type TinkEngine struct{}

var _ Engine = &TinkEngine{}

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

// GenerateAsymmetricKeyMaterial generates a secp256k1 private key and returns
// the raw 32-byte scalar as KeyMaterial.
func (e *TinkEngine) GenerateAsymmetricKeyMaterial(ctx context.Context, algorithm string) (KeyMaterial, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if algorithm != "EC_SIGN_SECP256K1_SHA256" {
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate secp256k1 key: %w", err)
	}
	return KeyMaterial(privKey.Serialize()), nil
}

// Sign signs a digest using the secp256k1 private key stored in keyMaterial.
// Returns a DER-encoded ECDSA signature.
func (e *TinkEngine) Sign(ctx context.Context, keyMaterial KeyMaterial, digest []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	privKey, _ := btcec.PrivKeyFromBytes(keyMaterial)
	sig := btcecdsa.Sign(privKey, digest)
	return sig.Serialize(), nil
}

// GetPublicKeyPEM returns the secp256k1 public key in PKIX/PEM format
// with the correct secp256k1 OID (1.3.132.0.10).
func (e *TinkEngine) GetPublicKeyPEM(ctx context.Context, keyMaterial KeyMaterial) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	privKey, _ := btcec.PrivKeyFromBytes(keyMaterial)
	pubKey := privKey.PubKey()

	derBytes, err := marshalSecp256k1PublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("marshal secp256k1 public key: %w", err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}
	return pem.EncodeToMemory(block), nil
}

// secp256k1 OID: 1.3.132.0.10
var oidSecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}

// id-ecPublicKey OID: 1.2.840.10045.2.1
var oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

// marshalSecp256k1PublicKey encodes a btcec public key into PKIX DER format
// with the secp256k1 named curve OID.
func marshalSecp256k1PublicKey(pub *btcec.PublicKey) ([]byte, error) {
	// Uncompressed point: 0x04 || X || Y
	x := pub.X()
	y := pub.Y()
	xBytes := padTo32(x.Bytes())
	yBytes := padTo32(y.Bytes())
	point := make([]byte, 1+64)
	point[0] = 0x04
	copy(point[1:33], xBytes)
	copy(point[33:65], yBytes)

	paramBytes, err := asn1.Marshal(oidSecp256k1)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidECPublicKey,
			Parameters: asn1.RawValue{FullBytes: paramBytes},
		},
		PublicKey: asn1.BitString{
			Bytes:     point,
			BitLength: len(point) * 8,
		},
	})
}

func padTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

func (e *TinkEngine) primitiveFromMaterial(material KeyMaterial) (tink.AEAD, error) {
	reader := bytes.NewReader(material)
	kh, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(reader))
	if err != nil {
		return nil, err
	}
	return aead.New(kh)
}
