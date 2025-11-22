package grpcserver_test

import (
	"context"
	"net"
	"testing"

	kmsapiv1 "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/winor30/fake-cloud-kms/kmscrypto"
	"github.com/winor30/fake-cloud-kms/service"
	"github.com/winor30/fake-cloud-kms/store/memory"
	grpcserver "github.com/winor30/fake-cloud-kms/transport/grpc"
)

func TestKMSEndToEndEncryptDecrypt(t *testing.T) {
	ctx := context.Background()
	addr, cleanup := startTestServer(t)
	defer cleanup()

	client, err := kmsapiv1.NewKeyManagementClient(ctx,
		option.WithEndpoint(addr),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
	)
	if err != nil {
		t.Fatalf("create kms client: %v", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Logf("close kms client: %v", err)
		}
	}()

	location := "projects/test/locations/global"
	_, err = client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{Parent: location, KeyRingId: "app"})
	if err != nil {
		t.Fatalf("create key ring: %v", err)
	}

	keyRingName := location + "/keyRings/app"
	cryptoKeyName := keyRingName + "/cryptoKeys/pair"
	_, err = client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      keyRingName,
		CryptoKeyId: "pair",
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
		},
	})
	if err != nil {
		t.Fatalf("create crypto key: %v", err)
	}

	msg := []byte("hello emulator")
	encResp, err := client.Encrypt(ctx, &kmspb.EncryptRequest{Name: cryptoKeyName, Plaintext: msg})
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	decResp, err := client.Decrypt(ctx, &kmspb.DecryptRequest{Name: cryptoKeyName, Ciphertext: encResp.GetCiphertext()})
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	if got := string(decResp.GetPlaintext()); got != string(msg) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, msg)
	}
}

func startTestServer(t *testing.T) (string, func()) {
	t.Helper()
	store := memory.New()
	engine := kmscrypto.NewTinkEngine()
	svc := service.New(store, engine)
	srv := grpcserver.New(svc)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		if err := srv.Serve(ctx, lis); err != nil {
			t.Logf("grpc server exited: %v", err)
		}
	}()

	cleanup := func() {
		cancel()
		_ = lis.Close()
	}

	return lis.Addr().String(), cleanup
}
