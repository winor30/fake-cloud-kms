package emulator_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/btcsuite/btcd/btcec/v2"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/winor30/fake-cloud-kms/crc"
	"github.com/winor30/fake-cloud-kms/pkg/api/emulator"
)

func TestStartAndEncryptDecrypt(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	inst, err := emulator.Start(ctx, emulator.Options{})
	if err != nil {
		t.Fatalf("start emulator: %v", err)
	}
	defer stopEmulator(t, inst)

	client := newClient(t, ctx, inst.Addr)
	defer closeClient(t, client)

	parent := "projects/demo/locations/global"
	keyRing := parent + "/keyRings/app"
	cryptoKey := keyRing + "/cryptoKeys/pair"

	if _, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    parent,
		KeyRingId: "app",
	}); err != nil {
		t.Fatalf("create key ring: %v", err)
	}
	if _, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      keyRing,
		CryptoKeyId: "pair",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	}); err != nil {
		t.Fatalf("create crypto key: %v", err)
	}

	msg := []byte("hello emulator")
	enc, err := client.Encrypt(ctx, &kmspb.EncryptRequest{Name: cryptoKey, Plaintext: msg})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	dec, err := client.Decrypt(ctx, &kmspb.DecryptRequest{Name: cryptoKey, Ciphertext: enc.GetCiphertext()})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got := string(dec.GetPlaintext()); got != string(msg) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, msg)
	}
}

func TestAsymmetricSignAndGetPublicKey(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	inst, err := emulator.Start(ctx, emulator.Options{})
	if err != nil {
		t.Fatalf("start emulator: %v", err)
	}
	defer stopEmulator(t, inst)

	client := newClient(t, ctx, inst.Addr)
	defer closeClient(t, client)

	parent := "projects/demo/locations/global"
	keyRingName := parent + "/keyRings/wallet"
	cryptoKeyName := keyRingName + "/cryptoKeys/signer"
	versionName := cryptoKeyName + "/cryptoKeyVersions/1"

	if _, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    parent,
		KeyRingId: "wallet",
	}); err != nil {
		t.Fatalf("create key ring: %v", err)
	}
	if _, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      keyRingName,
		CryptoKeyId: "signer",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256,
			},
		},
	}); err != nil {
		t.Fatalf("create crypto key: %v", err)
	}

	// GetPublicKey
	pubResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: versionName})
	if err != nil {
		t.Fatalf("get public key: %v", err)
	}
	if pubResp.GetPem() == "" {
		t.Fatal("PEM must not be empty")
	}
	if pubResp.GetAlgorithm() != kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256 {
		t.Fatalf("algorithm = %v, want EC_SIGN_SECP256K1_SHA256", pubResp.GetAlgorithm())
	}
	expectedPEMCRC := int64(crc.Compute([]byte(pubResp.GetPem())))
	if pubResp.GetPemCrc32C().GetValue() != expectedPEMCRC {
		t.Fatalf("pem_crc32c mismatch: got %d, want %d", pubResp.GetPemCrc32C().GetValue(), expectedPEMCRC)
	}

	// AsymmetricSign
	message := []byte("ethereum transaction data")
	digest := sha256.Sum256(message)
	digestCRC := crc.Compute(digest[:])

	signResp, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name:         versionName,
		Digest:       &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest[:]}},
		DigestCrc32C: wrapperspb.Int64(int64(digestCRC)),
	})
	if err != nil {
		t.Fatalf("asymmetric sign: %v", err)
	}
	if len(signResp.GetSignature()) == 0 {
		t.Fatal("signature must not be empty")
	}
	expectedSigCRC := int64(crc.Compute(signResp.GetSignature()))
	if signResp.GetSignatureCrc32C().GetValue() != expectedSigCRC {
		t.Fatalf("signature_crc32c mismatch: got %d, want %d", signResp.GetSignatureCrc32C().GetValue(), expectedSigCRC)
	}

	// Verify signature with public key
	pubKey := parseSecp256k1PEM(t, []byte(pubResp.GetPem()))
	ecPub := pubKey.ToECDSA()
	var sigDER struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(signResp.GetSignature(), &sigDER); err != nil {
		t.Fatalf("unmarshal DER: %v", err)
	}
	if !ecdsa.Verify(ecPub, digest[:], sigDER.R, sigDER.S) {
		t.Fatal("signature verification failed")
	}
}

func TestAsymmetricSeedBasedEmulator(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	seedYAML := `
projects:
  demo:
    locations:
      global:
        keyRings:
          wallet:
            cryptoKeys:
              eth-signer:
                purpose: ASYMMETRIC_SIGN
                algorithm: EC_SIGN_SECP256K1_SHA256
`
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "seed.yaml")
	if err := os.WriteFile(seedPath, []byte(seedYAML), 0o600); err != nil {
		t.Fatalf("write seed file: %v", err)
	}

	inst, err := emulator.Start(ctx, emulator.Options{SeedFile: seedPath})
	if err != nil {
		t.Fatalf("start emulator: %v", err)
	}
	defer stopEmulator(t, inst)

	client := newClient(t, ctx, inst.Addr)
	defer closeClient(t, client)

	versionName := "projects/demo/locations/global/keyRings/wallet/cryptoKeys/eth-signer/cryptoKeyVersions/1"

	pubResp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: versionName})
	if err != nil {
		t.Fatalf("get public key from seeded key: %v", err)
	}
	if pubResp.GetPem() == "" {
		t.Fatal("seeded key PEM must not be empty")
	}

	digest := sha256.Sum256([]byte("seeded test"))
	signResp, err := client.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
		Name:   versionName,
		Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest[:]}},
	})
	if err != nil {
		t.Fatalf("asymmetric sign with seeded key: %v", err)
	}
	if len(signResp.GetSignature()) == 0 {
		t.Fatal("signature must not be empty")
	}
}

// ---- helpers ----

func newClient(t *testing.T, ctx context.Context, addr string) *kms.KeyManagementClient {
	t.Helper()
	client, err := kms.NewKeyManagementClient(ctx,
		option.WithEndpoint(addr),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)
	if err != nil {
		t.Fatalf("create kms client: %v", err)
	}
	return client
}

func closeClient(t *testing.T, client *kms.KeyManagementClient) {
	t.Helper()
	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}
}

func stopEmulator(t *testing.T, inst *emulator.Instance) {
	t.Helper()
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	if err := inst.Stop(stopCtx); err != nil {
		t.Fatalf("stop emulator: %v", err)
	}
}

func parseSecp256k1PEM(t *testing.T, pemBytes []byte) *btcec.PublicKey {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}
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
	pubKey, err := btcec.ParsePubKey(pkixKey.PublicKey.Bytes)
	if err != nil {
		t.Fatalf("parse secp256k1 public key: %v", err)
	}
	return pubKey
}
