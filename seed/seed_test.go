package seed_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"

	"github.com/winor30/fake-cloud-kms/kmscrypto"
	"github.com/winor30/fake-cloud-kms/seed"
	"github.com/winor30/fake-cloud-kms/service"
	"github.com/winor30/fake-cloud-kms/store/memory"
)

func TestApplySymmetricSeed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := newService()

	seedYAML := `
projects:
  demo:
    locations:
      global:
        keyRings:
          app:
            cryptoKeys:
              pair:
                purpose: ENCRYPT_DECRYPT
`
	path := writeTempYAML(t, seedYAML)
	if err := seed.Apply(ctx, svc, path); err != nil {
		t.Fatalf("apply seed: %v", err)
	}

	ck, err := svc.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{
		Name: "projects/demo/locations/global/keyRings/app/cryptoKeys/pair",
	})
	if err != nil {
		t.Fatalf("get crypto key: %v", err)
	}
	if ck.GetPurpose() != kmspb.CryptoKey_ENCRYPT_DECRYPT {
		t.Fatalf("purpose = %v, want ENCRYPT_DECRYPT", ck.GetPurpose())
	}
}

func TestApplyAsymmetricSeed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := newService()

	seedYAML := `
projects:
  demo:
    locations:
      global:
        keyRings:
          wallet:
            cryptoKeys:
              signer:
                purpose: ASYMMETRIC_SIGN
                algorithm: EC_SIGN_SECP256K1_SHA256
`
	path := writeTempYAML(t, seedYAML)
	if err := seed.Apply(ctx, svc, path); err != nil {
		t.Fatalf("apply seed: %v", err)
	}

	ck, err := svc.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{
		Name: "projects/demo/locations/global/keyRings/wallet/cryptoKeys/signer",
	})
	if err != nil {
		t.Fatalf("get crypto key: %v", err)
	}
	if ck.GetPurpose() != kmspb.CryptoKey_ASYMMETRIC_SIGN {
		t.Fatalf("purpose = %v, want ASYMMETRIC_SIGN", ck.GetPurpose())
	}
	if ck.GetVersionTemplate().GetAlgorithm() != kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256 {
		t.Fatalf("algorithm = %v, want EC_SIGN_SECP256K1_SHA256", ck.GetVersionTemplate().GetAlgorithm())
	}

	// Verify GetPublicKey works on the seeded key
	versionName := ck.GetName() + "/cryptoKeyVersions/1"
	pubResp, err := svc.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: versionName})
	if err != nil {
		t.Fatalf("get public key: %v", err)
	}
	if pubResp.GetPem() == "" {
		t.Fatal("PEM must not be empty")
	}
}

func TestApplyUnsupportedPurpose(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := newService()

	seedYAML := `
projects:
  demo:
    locations:
      global:
        keyRings:
          app:
            cryptoKeys:
              bad:
                purpose: MAC
`
	path := writeTempYAML(t, seedYAML)
	if err := seed.Apply(ctx, svc, path); err == nil {
		t.Fatal("expected error for unsupported purpose")
	}
}

func TestApplyUnsupportedAlgorithm(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := newService()

	seedYAML := `
projects:
  demo:
    locations:
      global:
        keyRings:
          app:
            cryptoKeys:
              bad:
                purpose: ASYMMETRIC_SIGN
                algorithm: RSA_SIGN_PSS_2048_SHA256
`
	path := writeTempYAML(t, seedYAML)
	if err := seed.Apply(ctx, svc, path); err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func newService() service.KMSService {
	return service.New(memory.New(), kmscrypto.NewTinkEngine())
}

func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "seed.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}
