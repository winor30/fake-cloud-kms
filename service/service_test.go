package service_test

import (
	"context"
	"strings"
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
				CryptoKey:   &kmspb.CryptoKey{Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN},
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
