package memory

import (
	"context"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/winor30/fake-cloud-kms/kmscrypto"
)

func TestKeyRingLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := New()

	parent := "projects/demo/locations/global"
	keyRingName := parent + "/keyRings/app"

	t.Run("create and get", func(t *testing.T) {
		if err := store.CreateKeyRing(ctx, &kmspb.KeyRing{Name: keyRingName}); err != nil {
			t.Fatalf("create key ring: %v", err)
		}
		got, err := store.GetKeyRing(ctx, keyRingName)
		if err != nil {
			t.Fatalf("get key ring: %v", err)
		}
		if !proto.Equal(got, &kmspb.KeyRing{Name: keyRingName}) {
			t.Fatalf("get key ring mismatch: %v", got)
		}
		got.Name = "mutated"
		again, err := store.GetKeyRing(ctx, keyRingName)
		if err != nil {
			t.Fatalf("get key ring again: %v", err)
		}
		if again.GetName() != keyRingName {
			t.Fatalf("stored key ring should be immutable, got %q", again.GetName())
		}
	})

	t.Run("duplicate rejected", func(t *testing.T) {
		if err := store.CreateKeyRing(ctx, &kmspb.KeyRing{Name: keyRingName}); status.Code(err) != codes.AlreadyExists {
			t.Fatalf("duplicate key ring must return AlreadyExists, got %v", status.Code(err))
		}
	})

	t.Run("list filters by parent and clones results", func(t *testing.T) {
		otherParent := "projects/other/locations/global"
		if err := store.CreateKeyRing(ctx, &kmspb.KeyRing{Name: otherParent + "/keyRings/other"}); err != nil {
			t.Fatalf("create other key ring: %v", err)
		}

		list, err := store.ListKeyRings(ctx, parent)
		if err != nil {
			t.Fatalf("list key rings: %v", err)
		}
		if len(list) != 1 || list[0].GetName() != keyRingName {
			t.Fatalf("list key rings returned %#v, want only %s", list, keyRingName)
		}
		list[0].Name = "changed"
		filtered, err := store.ListKeyRings(ctx, parent)
		if err != nil {
			t.Fatalf("list key rings again: %v", err)
		}
		if filtered[0].GetName() != keyRingName {
			t.Fatalf("list results must be cloned, got %q", filtered[0].GetName())
		}
	})
}

func TestCryptoKeyLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := New()

	keyRingName := "projects/demo/locations/global/keyRings/app"
	if err := store.CreateKeyRing(ctx, &kmspb.KeyRing{Name: keyRingName}); err != nil {
		t.Fatalf("setup key ring: %v", err)
	}

	cryptoKeyName := keyRingName + "/cryptoKeys/pair"
	primaryVersion := &kmspb.CryptoKeyVersion{Name: cryptoKeyName + "/cryptoKeyVersions/1"}
	material := kmscrypto.KeyMaterial{1, 2, 3}
	cryptoKey := &kmspb.CryptoKey{
		Name:   cryptoKeyName,
		Labels: map[string]string{"team": "security"},
		Primary: &kmspb.CryptoKeyVersion{
			Name: primaryVersion.GetName(),
		},
	}

	t.Run("create and read copies", func(t *testing.T) {
		if err := store.CreateCryptoKey(ctx, keyRingName, cryptoKey, primaryVersion, material); err != nil {
			t.Fatalf("create crypto key: %v", err)
		}
		gotKey, err := store.GetCryptoKey(ctx, cryptoKeyName)
		if err != nil {
			t.Fatalf("get crypto key: %v", err)
		}
		if !proto.Equal(gotKey, cryptoKey) {
			t.Fatalf("crypto key mismatch: %v", gotKey)
		}
		gotKey.Labels["extra"] = "unexpected"
		immutable, err := store.GetCryptoKey(ctx, cryptoKeyName)
		if err != nil {
			t.Fatalf("get crypto key again: %v", err)
		}
		if immutable.GetLabels()["extra"] != "" {
			t.Fatalf("store must protect internal state from mutation")
		}
	})

	t.Run("duplicate rejected", func(t *testing.T) {
		if err := store.CreateCryptoKey(ctx, keyRingName, cryptoKey, primaryVersion, material); status.Code(err) != codes.AlreadyExists {
			t.Fatalf("duplicate crypto key must return AlreadyExists, got %v", status.Code(err))
		}
	})

	t.Run("list clones keys", func(t *testing.T) {
		keyList, err := store.ListCryptoKeys(ctx, keyRingName)
		if err != nil {
			t.Fatalf("list crypto keys: %v", err)
		}
		if len(keyList) != 1 || keyList[0].GetName() != cryptoKeyName {
			t.Fatalf("list crypto keys returned %#v, want only %s", keyList, cryptoKeyName)
		}
	})

	t.Run("versions are stored with material copy", func(t *testing.T) {
		version, keyMaterial, err := store.GetCryptoKeyVersion(ctx, primaryVersion.GetName())
		if err != nil {
			t.Fatalf("get crypto key version: %v", err)
		}
		if version.GetName() != primaryVersion.GetName() {
			t.Fatalf("version name mismatch: %s", version.GetName())
		}
		keyMaterial[0] = 99
		_, storedMaterial, err := store.GetCryptoKeyVersion(ctx, primaryVersion.GetName())
		if err != nil {
			t.Fatalf("get crypto key version again: %v", err)
		}
		if storedMaterial[0] != 1 {
			t.Fatalf("key material should be cloned, got %v", storedMaterial)
		}
	})

	t.Run("create new version and update primary", func(t *testing.T) {
		version2 := &kmspb.CryptoKeyVersion{Name: cryptoKeyName + "/cryptoKeyVersions/2"}
		if err := store.CreateCryptoKeyVersion(ctx, cryptoKeyName, version2, kmscrypto.KeyMaterial{4, 5, 6}); err != nil {
			t.Fatalf("create crypto key version: %v", err)
		}
		versions, err := store.ListCryptoKeyVersions(ctx, cryptoKeyName)
		if err != nil {
			t.Fatalf("list crypto key versions: %v", err)
		}
		if len(versions) != 2 || versions[0].GetName() != primaryVersion.GetName() || versions[1].GetName() != version2.GetName() {
			t.Fatalf("versions returned %#v", versions)
		}

		updated, err := store.SetPrimaryVersion(ctx, cryptoKeyName, version2.GetName())
		if err != nil {
			t.Fatalf("set primary version: %v", err)
		}
		if updated.GetPrimary().GetName() != version2.GetName() {
			t.Fatalf("primary not updated, got %s", updated.GetPrimary().GetName())
		}
	})

	t.Run("not found errors", func(t *testing.T) {
		if _, err := store.SetPrimaryVersion(ctx, "projects/demo/locations/global/keyRings/app/cryptoKeys/other", cryptoKeyName+"/cryptoKeyVersions/2"); status.Code(err) != codes.NotFound {
			t.Fatalf("set primary for missing key must return NotFound, got %v", status.Code(err))
		}
		if err := store.CreateCryptoKeyVersion(ctx, "projects/demo/locations/global/keyRings/app/cryptoKeys/missing", &kmspb.CryptoKeyVersion{Name: "projects/demo/locations/global/keyRings/app/cryptoKeys/missing/cryptoKeyVersions/1"}, kmscrypto.KeyMaterial{1}); status.Code(err) != codes.NotFound {
			t.Fatalf("create version for missing key must return NotFound, got %v", status.Code(err))
		}
	})
}
