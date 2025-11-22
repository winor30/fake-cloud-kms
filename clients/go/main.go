package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/docker/go-connections/nat"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type config struct {
	projectID   string
	locationID  string
	keyRingID   string
	cryptoKeyID string
	plaintext   string
	aad         string
}

func loadConfig() config {
	return config{
		projectID:   envOrDefault("GOOGLE_CLOUD_PROJECT", "demo"),
		locationID:  envOrDefault("KMS_LOCATION", "global"),
		keyRingID:   envOrDefault("KMS_KEY_RING", "app-ring"),
		cryptoKeyID: envOrDefault("KMS_CRYPTO_KEY", "app-key"),
		plaintext:   envOrDefault("KMS_PLAINTEXT", "Hello from Go client!"),
		aad:         envOrDefault("KMS_AAD", "go-client"),
	}
}

func envOrDefault(key, def string) string {
	val := os.Getenv(key)
	if val != "" {
		return val
	}
	return def
}

func ensureKeyRing(ctx context.Context, client *kms.KeyManagementClient, parent, keyRingID string) error {
	_, err := client.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{
		Parent:    parent,
		KeyRingId: keyRingID,
		KeyRing:   &kmspb.KeyRing{},
	})
	if status.Code(err) == codes.AlreadyExists {
		return nil
	}
	return err
}

func ensureCryptoKey(ctx context.Context, client *kms.KeyManagementClient, keyRingName, cryptoKeyID string) error {
	_, err := client.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      keyRingName,
		CryptoKeyId: cryptoKeyID,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: kmspb.CryptoKey_ENCRYPT_DECRYPT,
			VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
				Algorithm:       kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
				ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
			},
		},
	})
	if status.Code(err) == codes.AlreadyExists {
		return nil
	}
	return err
}

func startEmulator(ctx context.Context) (string, int, func(context.Context) error, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", 0, nil, fmt.Errorf("getwd: %w", err)
	}
	repoRoot := filepath.Clean(filepath.Join(wd, "..", ".."))

	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    repoRoot,
			Dockerfile: "Dockerfile",
		},
		ExposedPorts: []string{"9010/tcp"},
		WaitingFor: wait.ForListeningPort(
			nat.Port("9010/tcp"),
		).WithStartupTimeout(2 * time.Minute),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return "", 0, nil, fmt.Errorf("start container: %w", err)
	}

	host, err := container.Host(ctx)
	if err != nil {
		return "", 0, nil, fmt.Errorf("container host: %w", err)
	}
	mappedPort, err := container.MappedPort(ctx, "9010/tcp")
	if err != nil {
		return "", 0, nil, fmt.Errorf("mapped port: %w", err)
	}

	stop := func(stopCtx context.Context) error {
		return container.Terminate(stopCtx)
	}

	return host, mappedPort.Int(), stop, nil
}

func parseHostPort(endpoint string) (string, int, error) {
	host, portStr, ok := strings.Cut(endpoint, ":")
	if !ok {
		return "", 0, fmt.Errorf("endpoint must be host:port")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port: %w", err)
	}
	return host, port, nil
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cfg := loadConfig()

	host, port, stopEmulator, err := startEmulator(ctx)
	if err != nil {
		log.Fatalf("start emulator: %v", err)
	}
	defer func() {
		if stopErr := stopEmulator(context.Background()); stopErr != nil {
			log.Printf("stop emulator: %v", stopErr)
		}
	}()

	client, err := kms.NewKeyManagementClient(ctx,
		option.WithEndpoint(fmt.Sprintf("%s:%d", host, port)),
		option.WithoutAuthentication(),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
		option.WithGRPCDialOption(grpc.WithBlock()),
	)
	if err != nil {
		log.Fatalf("create kms client: %v", err)
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			log.Printf("close client: %v", closeErr)
		}
	}()

	parent := fmt.Sprintf("projects/%s/locations/%s", cfg.projectID, cfg.locationID)
	keyRingName := fmt.Sprintf("%s/keyRings/%s", parent, cfg.keyRingID)
	cryptoKeyName := fmt.Sprintf("%s/cryptoKeys/%s", keyRingName, cfg.cryptoKeyID)

	if err := ensureKeyRing(ctx, client, parent, cfg.keyRingID); err != nil {
		log.Fatalf("ensure key ring: %v", err)
	}
	if err := ensureCryptoKey(ctx, client, keyRingName, cfg.cryptoKeyID); err != nil {
		log.Fatalf("ensure crypto key: %v", err)
	}

	plaintext := []byte(cfg.plaintext)
	aad := []byte(cfg.aad)

	encryptResp, err := client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:                        cryptoKeyName,
		Plaintext:                   plaintext,
		AdditionalAuthenticatedData: aad,
	})
	if err != nil {
		log.Fatalf("encrypt: %v", err)
	}
	ciphertext := encryptResp.GetCiphertext()
	fmt.Println("ciphertext (base64):", base64.StdEncoding.EncodeToString(ciphertext))

	decryptResp, err := client.Decrypt(ctx, &kmspb.DecryptRequest{
		Name:                        cryptoKeyName,
		Ciphertext:                  ciphertext,
		AdditionalAuthenticatedData: aad,
	})
	if err != nil {
		log.Fatalf("decrypt: %v", err)
	}

	decrypted := decryptResp.GetPlaintext()
	if string(decrypted) != string(plaintext) {
		log.Fatalf("plaintext mismatch")
	}
	fmt.Println("plaintext:", string(decrypted))
}
