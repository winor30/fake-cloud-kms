package service_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/btcsuite/btcd/btcec/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/winor30/fake-cloud-kms/crc"
	"github.com/winor30/fake-cloud-kms/kmscrypto"
	"github.com/winor30/fake-cloud-kms/service"
	"github.com/winor30/fake-cloud-kms/store/memory"
)

func TestEncryptDecrypt(t *testing.T) {
	t.Parallel()

	t.Run("sets verification flags and crc", func(t *testing.T) {
		ctx := context.Background()
		svc, cryptoKeyName := setupKey(t)

		plaintext := []byte("hello emulator")
		aad := []byte("aad-data")

		encResp := mustEncrypt(t, ctx, svc, &kmspb.EncryptRequest{
			Name:                              cryptoKeyName,
			Plaintext:                         plaintext,
			PlaintextCrc32C:                   wrapperspb.Int64(int64(crc.Compute(plaintext))),
			AdditionalAuthenticatedData:       aad,
			AdditionalAuthenticatedDataCrc32C: wrapperspb.Int64(int64(crc.Compute(aad))),
		})

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
		decResp := mustDecrypt(t, ctx, svc, &kmspb.DecryptRequest{
			Name:                              cryptoKeyName,
			Ciphertext:                        ciphertext,
			CiphertextCrc32C:                  wrapperspb.Int64(int64(crc.Compute(ciphertext))),
			AdditionalAuthenticatedData:       aad,
			AdditionalAuthenticatedDataCrc32C: wrapperspb.Int64(int64(crc.Compute(aad))),
		})

		if got := string(decResp.GetPlaintext()); got != string(plaintext) {
			t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
		}
		if decResp.GetPlaintextCrc32C().GetValue() == 0 {
			t.Fatalf("plaintext_crc32c must be set")
		}
	})

	t.Run("rejects checksum mismatch", func(t *testing.T) {
		ctx := context.Background()
		svc, cryptoKeyName := setupKey(t)

		plaintext := []byte("hello emulator")
		badChecksum := wrapperspb.Int64(int64(crc.Compute(plaintext) + 1))

		_, err := svc.Encrypt(ctx, &kmspb.EncryptRequest{
			Name:            cryptoKeyName,
			Plaintext:       plaintext,
			PlaintextCrc32C: badChecksum,
		})
		requireStatusCode(t, err, codes.InvalidArgument)
	})
}

func TestListResources(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := newTestService()

	parent := "projects/demo/locations/global"
	keyRing := createKeyRing(t, svc, parent, "app")
	createKeyRing(t, svc, "projects/demo/locations/us", "backup")

	keyA := createCryptoKey(t, svc, keyRing, "alpha")
	keyB := createCryptoKey(t, svc, keyRing, "beta")

	t.Run("filters key rings by parent", func(t *testing.T) {
		rings, err := svc.ListKeyRings(ctx, &kmspb.ListKeyRingsRequest{Parent: parent})
		if err != nil {
			t.Fatalf("list key rings: %v", err)
		}
		if len(rings.GetKeyRings()) != 1 || rings.GetKeyRings()[0].GetName() != keyRing {
			t.Fatalf("list key rings returned %#v", rings.GetKeyRings())
		}
	})

	t.Run("lists crypto keys in order", func(t *testing.T) {
		keys, err := svc.ListCryptoKeys(ctx, &kmspb.ListCryptoKeysRequest{Parent: keyRing})
		if err != nil {
			t.Fatalf("list crypto keys: %v", err)
		}
		list := keys.GetCryptoKeys()
		if len(list) != 2 || list[0].GetName() != keyA || list[1].GetName() != keyB {
			names := []string{list[0].GetName(), list[1].GetName()}
			t.Fatalf("list crypto keys returned %v", names)
		}
	})

	t.Run("lists crypto key versions", func(t *testing.T) {
		versions, err := svc.ListCryptoKeyVersions(ctx, &kmspb.ListCryptoKeyVersionsRequest{Parent: keyA})
		if err != nil {
			t.Fatalf("list crypto key versions: %v", err)
		}
		if len(versions.GetCryptoKeyVersions()) != 1 || versions.GetCryptoKeyVersions()[0].GetName() != keyA+"/cryptoKeyVersions/1" {
			t.Fatalf("versions returned %#v", versions.GetCryptoKeyVersions())
		}
	})

	t.Run("pagination is not implemented", func(t *testing.T) {
		_, err := svc.ListKeyRings(ctx, &kmspb.ListKeyRingsRequest{Parent: parent, PageToken: "next"})
		requireStatusCode(t, err, codes.Unimplemented)

		_, err = svc.ListCryptoKeyVersions(ctx, &kmspb.ListCryptoKeyVersionsRequest{Parent: keyA, PageToken: "token"})
		requireStatusCode(t, err, codes.Unimplemented)
	})
}

func TestCreateVersionAndUpdatePrimary(t *testing.T) {
	t.Parallel()

	t.Run("rejects invalid parent", func(t *testing.T) {
		ctx := context.Background()
		svc := newTestService()

		_, err := svc.CreateCryptoKeyVersion(ctx, &kmspb.CreateCryptoKeyVersionRequest{Parent: "projects/demo/locations/global/keyRings/app/cryptoKeys/!invalid"})
		requireStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("creates next version and updates primary", func(t *testing.T) {
		ctx := context.Background()
		svc, cryptoKeyName := setupKey(t)

		version, err := svc.CreateCryptoKeyVersion(ctx, &kmspb.CreateCryptoKeyVersionRequest{Parent: cryptoKeyName})
		if err != nil {
			t.Fatalf("create crypto key version: %v", err)
		}
		if !strings.HasSuffix(version.GetName(), "/cryptoKeyVersions/2") {
			t.Fatalf("expected next version ID, got %s", version.GetName())
		}

		ck, err := svc.UpdateCryptoKeyPrimaryVersion(ctx, &kmspb.UpdateCryptoKeyPrimaryVersionRequest{
			Name:               cryptoKeyName,
			CryptoKeyVersionId: "2",
		})
		if err != nil {
			t.Fatalf("update primary: %v", err)
		}
		if ck.GetPrimary().GetName() != version.GetName() {
			t.Fatalf("primary not updated, got %s", ck.GetPrimary().GetName())
		}
	})

	t.Run("requires version id when updating", func(t *testing.T) {
		ctx := context.Background()
		svc, cryptoKeyName := setupKey(t)

		_, err := svc.UpdateCryptoKeyPrimaryVersion(ctx, &kmspb.UpdateCryptoKeyPrimaryVersionRequest{Name: cryptoKeyName})
		requireStatusCode(t, err, codes.InvalidArgument)
	})
}

func TestDecryptRejectsCrossKeyCiphertext(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := newTestService()
	parent := "projects/demo/locations/global"
	keyRing := createKeyRing(t, svc, parent, "app")

	sourceKey := createCryptoKey(t, svc, keyRing, "alpha")
	targetKey := createCryptoKey(t, svc, keyRing, "beta")

	enc := mustEncrypt(t, ctx, svc, &kmspb.EncryptRequest{
		Name:      sourceKey,
		Plaintext: []byte("isolation"),
	})

	cases := []struct {
		name      string
		key       string
		wantErr   codes.Code
		wantPlain string
	}{
		{name: "wrong key", key: targetKey, wantErr: codes.FailedPrecondition},
		{name: "correct key", key: sourceKey, wantPlain: "isolation"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := svc.Decrypt(ctx, &kmspb.DecryptRequest{
				Name:       tc.key,
				Ciphertext: enc.GetCiphertext(),
			})
			if tc.wantErr != codes.OK {
				requireStatusCode(t, err, tc.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if string(resp.GetPlaintext()) != tc.wantPlain {
				t.Fatalf("plaintext mismatch: %s", resp.GetPlaintext())
			}
		})
	}
}

func TestCreateCryptoKeyCopiesLabels(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := newTestService()
	keyRing := createKeyRing(t, svc, "projects/demo/locations/global", "labels")

	labels := map[string]string{"env": "dev"}
	req := &kmspb.CreateCryptoKeyRequest{
		Parent:      keyRing,
		CryptoKeyId: "pair",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
			Labels:  labels,
		},
	}
	created, err := svc.CreateCryptoKey(ctx, req)
	if err != nil {
		t.Fatalf("create crypto key: %v", err)
	}
	t.Run("copies caller labels", func(t *testing.T) {
		if created.GetLabels()["env"] != "dev" {
			t.Fatalf("labels not copied")
		}
	})

	t.Run("stores immutable copy", func(t *testing.T) {
		labels["env"] = "prod"
		created.Labels["new"] = "value"

		stored, err := svc.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: created.GetName()})
		if err != nil {
			t.Fatalf("get crypto key: %v", err)
		}
		if stored.GetLabels()["env"] != "dev" {
			t.Fatalf("stored labels mutated: %v", stored.GetLabels())
		}
		if stored.GetLabels()["new"] != "" {
			t.Fatalf("store must not persist caller mutations: %v", stored.GetLabels())
		}
	})
}

func TestCreateCryptoKeyValidations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := newTestService()
	keyRing := createKeyRing(t, svc, "projects/demo/locations/global", "validate")

	for _, tc := range []struct {
		name string
		req  *kmspb.CreateCryptoKeyRequest
	}{
		{
			name: "invalid parent",
			req: &kmspb.CreateCryptoKeyRequest{
				Parent:      "projects/demo/locations/!/keyRings/app",
				CryptoKeyId: "bad",
				CryptoKey:   &kmspb.CryptoKey{Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT},
			},
		},
		{
			name: "missing id",
			req: &kmspb.CreateCryptoKeyRequest{
				Parent: keyRing,
				CryptoKey: &kmspb.CryptoKey{
					Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
				},
			},
		},
		{
			name: "missing crypto key",
			req: &kmspb.CreateCryptoKeyRequest{
				Parent:      keyRing,
				CryptoKeyId: "id",
			},
		},
		{
			name: "unsupported purpose",
			req: &kmspb.CreateCryptoKeyRequest{
				Parent:      keyRing,
				CryptoKeyId: "id",
				CryptoKey:   &kmspb.CryptoKey{Purpose: kmspb.CryptoKey_ASYMMETRIC_DECRYPT},
			},
		},
		{
			name: "asymmetric sign with wrong algorithm",
			req: &kmspb.CreateCryptoKeyRequest{
				Parent:      keyRing,
				CryptoKeyId: "id",
				CryptoKey: &kmspb.CryptoKey{
					Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
					VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
						Algorithm: kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.CreateCryptoKey(ctx, tc.req)
			requireStatusCode(t, err, codes.InvalidArgument)
		})
	}
}

func TestGetOperations(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, cryptoKeyName := setupKey(t)

	keyRingName := "projects/demo/locations/global/keyRings/app"
	versionName := cryptoKeyName + "/cryptoKeyVersions/1"

	for _, tc := range []struct {
		name    string
		valid   string
		invalid string
		call    func(context.Context, service.KMSService, string) error
	}{
		{
			name:    "GetKeyRing",
			valid:   keyRingName,
			invalid: "invalid",
			call: func(ctx context.Context, svc service.KMSService, name string) error {
				_, err := svc.GetKeyRing(ctx, &kmspb.GetKeyRingRequest{Name: name})
				return err
			},
		},
		{
			name:    "GetCryptoKey",
			valid:   cryptoKeyName,
			invalid: "invalid",
			call: func(ctx context.Context, svc service.KMSService, name string) error {
				_, err := svc.GetCryptoKey(ctx, &kmspb.GetCryptoKeyRequest{Name: name})
				return err
			},
		},
		{
			name:    "GetCryptoKeyVersion",
			valid:   versionName,
			invalid: "invalid",
			call: func(ctx context.Context, svc service.KMSService, name string) error {
				_, err := svc.GetCryptoKeyVersion(ctx, &kmspb.GetCryptoKeyVersionRequest{Name: name})
				return err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(ctx, svc, tc.valid); err != nil {
				t.Fatalf("%s valid name: %v", tc.name, err)
			}
			err := tc.call(ctx, svc, tc.invalid)
			requireStatusCode(t, err, codes.InvalidArgument)
		})
	}
}

func TestAsymmetricSignAndGetPublicKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, versionName := setupAsymmetricKey(t)

	t.Run("get public key returns PEM with CRC32C", func(t *testing.T) {
		pubResp, err := svc.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: versionName})
		if err != nil {
			t.Fatalf("get public key: %v", err)
		}
		if pubResp.GetPem() == "" {
			t.Fatal("PEM must not be empty")
		}
		if pubResp.GetAlgorithm() != kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256 {
			t.Fatalf("algorithm = %v, want EC_SIGN_SECP256K1_SHA256", pubResp.GetAlgorithm())
		}
		if pubResp.GetName() != versionName {
			t.Fatalf("name = %s, want %s", pubResp.GetName(), versionName)
		}
		// Verify CRC32C
		expectedCRC := int64(crc.Compute([]byte(pubResp.GetPem())))
		if pubResp.GetPemCrc32C().GetValue() != expectedCRC {
			t.Fatalf("pem_crc32c mismatch: got %d, want %d", pubResp.GetPemCrc32C().GetValue(), expectedCRC)
		}
	})

	t.Run("asymmetric sign returns DER signature with CRC32C", func(t *testing.T) {
		digest := sha256.Sum256([]byte("test message"))
		digestCRC := crc.Compute(digest[:])

		signResp, err := svc.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
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
		if !signResp.GetVerifiedDigestCrc32C() {
			t.Fatal("verified_digest_crc32c should be true")
		}
		// Verify signature CRC32C
		expectedCRC := int64(crc.Compute(signResp.GetSignature()))
		if signResp.GetSignatureCrc32C().GetValue() != expectedCRC {
			t.Fatalf("signature_crc32c mismatch: got %d, want %d", signResp.GetSignatureCrc32C().GetValue(), expectedCRC)
		}

		// Verify the signature with the public key
		pubResp, err := svc.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: versionName})
		if err != nil {
			t.Fatalf("get public key: %v", err)
		}
		pubKey := parseSecp256k1PEM(t, []byte(pubResp.GetPem()))
		ecPub := pubKey.ToECDSA()

		var sigDER struct{ R, S *big.Int }
		if _, err := asn1.Unmarshal(signResp.GetSignature(), &sigDER); err != nil {
			t.Fatalf("unmarshal DER: %v", err)
		}
		if !ecdsa.Verify(ecPub, digest[:], sigDER.R, sigDER.S) {
			t.Fatal("signature verification failed")
		}
	})

	t.Run("rejects missing digest", func(t *testing.T) {
		_, err := svc.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
			Name: versionName,
		})
		requireStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("rejects non-sha256 digest", func(t *testing.T) {
		_, err := svc.AsymmetricSign(ctx, &kmspb.AsymmetricSignRequest{
			Name:   versionName,
			Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha384{Sha384: make([]byte, 48)}},
		})
		requireStatusCode(t, err, codes.InvalidArgument)
	})

	t.Run("rejects GetPublicKey on symmetric key", func(t *testing.T) {
		symSvc, symKeyName := setupKey(t)
		symVersionName := symKeyName + "/cryptoKeyVersions/1"
		_, err := symSvc.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: symVersionName})
		requireStatusCode(t, err, codes.FailedPrecondition)
	})
}

func TestCreateAsymmetricCryptoKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc := newTestService()
	keyRing := createKeyRing(t, svc, "projects/demo/locations/global", "asym")

	ck, err := svc.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      keyRing,
		CryptoKeyId: "signer",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256,
			},
		},
	})
	if err != nil {
		t.Fatalf("create asymmetric crypto key: %v", err)
	}

	if ck.GetPurpose() != kmspb.CryptoKey_ASYMMETRIC_SIGN {
		t.Fatalf("purpose = %v, want ASYMMETRIC_SIGN", ck.GetPurpose())
	}
	if ck.GetVersionTemplate().GetAlgorithm() != kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256 {
		t.Fatalf("algorithm = %v, want EC_SIGN_SECP256K1_SHA256", ck.GetVersionTemplate().GetAlgorithm())
	}
}

func TestCreateAsymmetricCryptoKeyVersion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	svc, versionName := setupAsymmetricKey(t)

	// versionName ends with /cryptoKeyVersions/1, get the crypto key name
	cryptoKeyName := versionName[:strings.LastIndex(versionName, "/cryptoKeyVersions/")]

	version, err := svc.CreateCryptoKeyVersion(ctx, &kmspb.CreateCryptoKeyVersionRequest{Parent: cryptoKeyName})
	if err != nil {
		t.Fatalf("create crypto key version: %v", err)
	}
	if version.GetAlgorithm() != kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256 {
		t.Fatalf("new version algorithm = %v, want EC_SIGN_SECP256K1_SHA256", version.GetAlgorithm())
	}
	if !strings.HasSuffix(version.GetName(), "/cryptoKeyVersions/2") {
		t.Fatalf("expected version 2, got %s", version.GetName())
	}
}

// ---- helpers ----

func mustEncrypt(t *testing.T, ctx context.Context, svc service.KMSService, req *kmspb.EncryptRequest) *kmspb.EncryptResponse {
	t.Helper()
	resp, err := svc.Encrypt(ctx, req)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	return resp
}

func mustDecrypt(t *testing.T, ctx context.Context, svc service.KMSService, req *kmspb.DecryptRequest) *kmspb.DecryptResponse {
	t.Helper()
	resp, err := svc.Decrypt(ctx, req)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	return resp
}

func requireStatusCode(t *testing.T, err error, code codes.Code) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("status code = %v, want %v", status.Code(err), code)
	}
}

func setupKey(t *testing.T) (service.KMSService, string) {
	t.Helper()
	svc := newTestService()
	keyRing := createKeyRing(t, svc, "projects/demo/locations/global", "app")
	cryptoKey := createCryptoKey(t, svc, keyRing, "pair")
	return svc, cryptoKey
}

func setupAsymmetricKey(t *testing.T) (service.KMSService, string) {
	t.Helper()
	svc := newTestService()
	keyRing := createKeyRing(t, svc, "projects/demo/locations/global", "asym")
	cryptoKeyName := createAsymmetricCryptoKey(t, svc, keyRing, "signer")
	return svc, cryptoKeyName + "/cryptoKeyVersions/1"
}

func newTestService() service.KMSService {
	return service.New(memory.New(), kmscrypto.NewTinkEngine())
}

func createKeyRing(t *testing.T, svc service.KMSService, parent, id string) string {
	t.Helper()
	name := parent + "/keyRings/" + id
	if _, err := svc.CreateKeyRing(context.Background(), &kmspb.CreateKeyRingRequest{Parent: parent, KeyRingId: id}); err != nil {
		t.Fatalf("create key ring %s: %v", name, err)
	}
	return name
}

func createCryptoKey(t *testing.T, svc service.KMSService, keyRingName, id string) string {
	t.Helper()
	name := keyRingName + "/cryptoKeys/" + id
	if _, err := svc.CreateCryptoKey(context.Background(), &kmspb.CreateCryptoKeyRequest{
		Parent:      keyRingName,
		CryptoKeyId: id,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	}); err != nil {
		t.Fatalf("create crypto key %s: %v", name, err)
	}
	return name
}

func createAsymmetricCryptoKey(t *testing.T, svc service.KMSService, keyRingName, id string) string {
	t.Helper()
	name := keyRingName + "/cryptoKeys/" + id
	if _, err := svc.CreateCryptoKey(context.Background(), &kmspb.CreateCryptoKeyRequest{
		Parent:      keyRingName,
		CryptoKeyId: id,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256,
			},
		},
	}); err != nil {
		t.Fatalf("create asymmetric crypto key %s: %v", name, err)
	}
	return name
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
