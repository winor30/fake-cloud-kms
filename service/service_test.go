package service_test

import (
	"context"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/winor30/fake-cloud-kms/crc"
	"github.com/winor30/fake-cloud-kms/kmscrypto"
	"github.com/winor30/fake-cloud-kms/service"
	"github.com/winor30/fake-cloud-kms/store/memory"
)

func TestEncryptDecryptVerifiedFlags(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, cryptoKeyName := setupKey(t)

	plaintext := []byte("hello emulator")
	aad := []byte("aad-data")

	encResp, err := svc.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:                              cryptoKeyName,
		Plaintext:                         plaintext,
		PlaintextCrc32C:                   wrapperspb.Int64(int64(crc.Compute(plaintext))),
		AdditionalAuthenticatedData:       aad,
		AdditionalAuthenticatedDataCrc32C: wrapperspb.Int64(int64(crc.Compute(aad))),
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !encResp.GetVerifiedPlaintextCrc32C() {
		t.Fatalf("verified_plaintext_crc32c = false, want true")
	}
	if !encResp.GetVerifiedAdditionalAuthenticatedDataCrc32C() {
		t.Fatalf("verified_aad_crc32c = false, want true")
	}
	if encResp.GetCiphertextCrc32C().GetValue() == 0 {
		t.Fatalf("ciphertext_crc32c must be set")
	}

	ciphertext := encResp.GetCiphertext()
	decResp, err := svc.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:                              cryptoKeyName,
		Ciphertext:                        ciphertext,
		CiphertextCrc32C:                  wrapperspb.Int64(int64(crc.Compute(ciphertext))),
		AdditionalAuthenticatedData:       aad,
		AdditionalAuthenticatedDataCrc32C: wrapperspb.Int64(int64(crc.Compute(aad))),
	})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got := string(decResp.GetPlaintext()); got != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
	}
	if decResp.GetPlaintextCrc32C().GetValue() == 0 {
		t.Fatalf("plaintext_crc32c must be set")
	}
}

func TestEncryptChecksumMismatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, cryptoKeyName := setupKey(t)

	plaintext := []byte("hello emulator")
	badChecksum := wrapperspb.Int64(int64(crc.Compute(plaintext) + 1))

	_, err := svc.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:            cryptoKeyName,
		Plaintext:       plaintext,
		PlaintextCrc32C: badChecksum,
	})
	if err == nil {
		t.Fatalf("expected checksum error")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("status code = %v, want %v", status.Code(err), codes.InvalidArgument)
	}
}

func setupKey(t *testing.T) (service.KMSService, string) {
	t.Helper()
	store := memory.New()
	engine := kmscrypto.NewTinkEngine()
	svc := service.New(store, engine)

	ctx := context.Background()
	_, err := svc.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    "projects/demo/locations/global",
		KeyRingId: "app",
	})
	if err != nil {
		t.Fatalf("setup key ring: %v", err)
	}
	_, err = svc.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      "projects/demo/locations/global/keyRings/app",
		CryptoKeyId: "pair",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})
	if err != nil {
		t.Fatalf("setup crypto key: %v", err)
	}

	return svc, "projects/demo/locations/global/keyRings/app/cryptoKeys/pair"
}
