package emulator_test

import (
	"context"
	"testing"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

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
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		if err := inst.Stop(stopCtx); err != nil {
			t.Fatalf("stop emulator: %v", err)
		}
	}()

	client, err := kms.NewKeyManagementClient(ctx,
		option.WithEndpoint(inst.Addr),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)
	if err != nil {
		t.Fatalf("create kms client: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Fatalf("close client: %v", err)
		}
	}()

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
