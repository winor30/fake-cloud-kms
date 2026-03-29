package kmscrypto

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
)

func TestTinkEngineRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	engine := NewTinkEngine()

	material, err := engine.GenerateKeyMaterial(ctx)
	if err != nil {
		t.Fatalf("generate key material: %v", err)
	}

	tests := []struct {
		name string
		aad  []byte
		want []byte
		err  bool
	}{
		{name: "success", aad: []byte("aad"), want: []byte("secure payload")},
		{name: "aad mismatch", aad: []byte("bad-aad"), want: nil, err: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := engine.Encrypt(ctx, material, []byte("secure payload"), []byte("aad"))
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			got, err := engine.Decrypt(ctx, material, ciphertext, tt.aad)
			if tt.err {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("plaintext mismatch: got %q want %q", got, tt.want)
			}
		})
	}
}

func TestTinkEngineContextCancellation(t *testing.T) {
	t.Parallel()
	engine := NewTinkEngine()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := engine.GenerateKeyMaterial(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("GenerateKeyMaterial: expected context cancellation, got %v", err)
	}

	material, err := engine.GenerateKeyMaterial(context.Background())
	if err != nil {
		t.Fatalf("generate key material: %v", err)
	}

	if _, err := engine.Encrypt(cancelled, material, []byte("data"), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Encrypt: expected context cancellation, got %v", err)
	}
	if _, err := engine.Decrypt(cancelled, material, []byte("ciphertext"), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Decrypt: expected context cancellation, got %v", err)
	}
}

func TestTinkEngineGenerateSecp256k1(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	engine := NewTinkEngine()

	material, err := engine.GenerateAsymmetricKeyMaterial(ctx, "EC_SIGN_SECP256K1_SHA256")
	if err != nil {
		t.Fatalf("generate asymmetric key material: %v", err)
	}
	if len(material) == 0 {
		t.Fatal("key material must not be empty")
	}
}

func TestTinkEngineGenerateSecp256k1_UnsupportedAlgorithm(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	engine := NewTinkEngine()

	_, err := engine.GenerateAsymmetricKeyMaterial(ctx, "RSA_SIGN_PSS_2048_SHA256")
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestTinkEngineSignAndVerify(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	engine := NewTinkEngine()

	material, err := engine.GenerateAsymmetricKeyMaterial(ctx, "EC_SIGN_SECP256K1_SHA256")
	if err != nil {
		t.Fatalf("generate key material: %v", err)
	}

	digest := sha256.Sum256([]byte("hello world"))
	sig, err := engine.Sign(ctx, material, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature must not be empty")
	}

	// Verify DER-encoded signature with the public key
	pemBytes, err := engine.GetPublicKeyPEM(ctx, material)
	if err != nil {
		t.Fatalf("get public key pem: %v", err)
	}

	pubKey := parsePEMPublicKey(t, pemBytes)

	// Parse DER signature
	var sigDER struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(sig, &sigDER); err != nil {
		t.Fatalf("unmarshal DER signature: %v", err)
	}

	// Convert btcec public key to stdlib ecdsa.PublicKey for verification
	ecPub := pubKey.ToECDSA()
	if !ecdsa.Verify(ecPub, digest[:], sigDER.R, sigDER.S) {
		t.Fatal("signature verification failed")
	}
}

func TestTinkEngineGetPublicKeyPEM(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	engine := NewTinkEngine()

	material, err := engine.GenerateAsymmetricKeyMaterial(ctx, "EC_SIGN_SECP256K1_SHA256")
	if err != nil {
		t.Fatalf("generate key material: %v", err)
	}

	pemBytes, err := engine.GetPublicKeyPEM(ctx, material)
	if err != nil {
		t.Fatalf("get public key pem: %v", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatalf("expected PUBLIC KEY PEM block, got %v", block)
	}

	// Verify the OID is secp256k1 (1.3.132.0.10) by parsing the DER
	var pkixKey struct {
		Algorithm struct {
			OID        asn1.ObjectIdentifier
			Parameters asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(block.Bytes, &pkixKey); err != nil {
		t.Fatalf("unmarshal PKIX: %v", err)
	}

	secp256k1OID := asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	if !pkixKey.Algorithm.Parameters.Equal(secp256k1OID) {
		t.Fatalf("expected secp256k1 OID %v, got %v", secp256k1OID, pkixKey.Algorithm.Parameters)
	}

	// Verify the public key can be parsed back
	pubKey := parsePEMPublicKey(t, pemBytes)
	if pubKey.X() == nil || pubKey.Y() == nil {
		t.Fatal("public key coordinates must not be nil")
	}
}

func TestTinkEngineSignDeterministicPublicKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	engine := NewTinkEngine()

	material, err := engine.GenerateAsymmetricKeyMaterial(ctx, "EC_SIGN_SECP256K1_SHA256")
	if err != nil {
		t.Fatalf("generate key material: %v", err)
	}

	pem1, err := engine.GetPublicKeyPEM(ctx, material)
	if err != nil {
		t.Fatalf("get public key pem 1: %v", err)
	}
	pem2, err := engine.GetPublicKeyPEM(ctx, material)
	if err != nil {
		t.Fatalf("get public key pem 2: %v", err)
	}
	if !bytes.Equal(pem1, pem2) {
		t.Fatal("public key PEM should be deterministic for same material")
	}
}

func TestTinkEngineAsymmetricContextCancellation(t *testing.T) {
	t.Parallel()
	engine := NewTinkEngine()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := engine.GenerateAsymmetricKeyMaterial(cancelled, "EC_SIGN_SECP256K1_SHA256"); !errors.Is(err, context.Canceled) {
		t.Fatalf("GenerateAsymmetricKeyMaterial: expected context cancellation, got %v", err)
	}

	material, err := engine.GenerateAsymmetricKeyMaterial(context.Background(), "EC_SIGN_SECP256K1_SHA256")
	if err != nil {
		t.Fatalf("generate key material: %v", err)
	}

	if _, err := engine.Sign(cancelled, material, []byte("digest")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Sign: expected context cancellation, got %v", err)
	}
	if _, err := engine.GetPublicKeyPEM(cancelled, material); !errors.Is(err, context.Canceled) {
		t.Fatalf("GetPublicKeyPEM: expected context cancellation, got %v", err)
	}
}

// parsePEMPublicKey decodes a PEM-encoded secp256k1 public key.
func parsePEMPublicKey(t *testing.T, pemBytes []byte) *btcec.PublicKey {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}

	// Parse the PKIX structure manually since x509 doesn't support secp256k1
	var pkixKey struct {
		Algorithm struct {
			OID        asn1.ObjectIdentifier
			Parameters asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(block.Bytes, &pkixKey); err != nil {
		t.Fatalf("unmarshal PKIX: %v", err)
	}

	// The public key bytes are the uncompressed point
	pointBytes := pkixKey.PublicKey.Bytes
	pubKey, err := btcec.ParsePubKey(pointBytes)
	if err != nil {
		t.Fatalf("parse secp256k1 public key: %v", err)
	}
	return pubKey
}
