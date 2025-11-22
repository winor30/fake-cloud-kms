package seed

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"
)

// ServiceAPI defines the subset of the KMS service needed for seeding.
type ServiceAPI interface {
	CreateKeyRing(context.Context, *kmspb.CreateKeyRingRequest) (*kmspb.KeyRing, error)
	CreateCryptoKey(context.Context, *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error)
	CreateCryptoKeyVersion(context.Context, *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error)
}

// Apply loads the provided YAML document and provisions resources.
func Apply(ctx context.Context, svc ServiceAPI, path string) error {
	if err := ensureYAML(path); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read seed file: %w", err)
	}
	var doc document
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse seed file: %w", err)
	}
	for projectID, project := range doc.Projects {
		for locationID, location := range project.Locations {
			parent := fmt.Sprintf("projects/%s/locations/%s", projectID, locationID)
			for keyRingID, keyRing := range location.KeyRings {
				if err := createKeyRing(ctx, svc, parent, keyRingID); err != nil {
					return err
				}
				keyRingName := fmt.Sprintf("%s/keyRings/%s", parent, keyRingID)
				for cryptoKeyID, cryptoKey := range keyRing.CryptoKeys {
					if err := createCryptoKey(ctx, svc, keyRingName, cryptoKeyID, cryptoKey); err != nil {
						return err
					}
					for i := 1; i < len(cryptoKey.Versions); i++ {
						if err := createVersion(ctx, svc, fmt.Sprintf("%s/cryptoKeys/%s", keyRingName, cryptoKeyID)); err != nil {
							return err
						}
					}
				}
			}
		}
	}
	return nil
}

func createKeyRing(ctx context.Context, svc ServiceAPI, parent, id string) error {
	_, err := svc.CreateKeyRing(ctx, &kmspb.CreateKeyRingRequest{Parent: parent, KeyRingId: id})
	if err != nil && status.Code(err) != codes.AlreadyExists {
		return fmt.Errorf("create key ring %s/%s: %w", parent, id, err)
	}
	if err == nil {
		slog.InfoContext(ctx, "seeded key ring", "keyRing", fmt.Sprintf("%s/keyRings/%s", parent, id))
	}
	return nil
}

func createCryptoKey(ctx context.Context, svc ServiceAPI, keyRingName, id string, seed CryptoKeySeed) error {
	purpose := kmspb.CryptoKey_ENCRYPT_DECRYPT
	if seed.Purpose != "" && seed.Purpose != "ENCRYPT_DECRYPT" {
		return fmt.Errorf("unsupported purpose in seed for %s/%s: %s", keyRingName, id, seed.Purpose)
	}
	_, err := svc.CreateCryptoKey(ctx, &kmspb.CreateCryptoKeyRequest{
		Parent:      keyRingName,
		CryptoKeyId: id,
		CryptoKey: &kmspb.CryptoKey{
			Purpose: purpose,
			Labels:  seed.Labels,
		},
	})
	if err != nil && status.Code(err) != codes.AlreadyExists {
		return fmt.Errorf("create crypto key %s/%s: %w", keyRingName, id, err)
	}
	if err == nil {
		slog.InfoContext(ctx, "seeded crypto key", "cryptoKey", fmt.Sprintf("%s/cryptoKeys/%s", keyRingName, id))
	}
	return nil
}

func createVersion(ctx context.Context, svc ServiceAPI, cryptoKeyName string) error {
	_, err := svc.CreateCryptoKeyVersion(ctx, &kmspb.CreateCryptoKeyVersionRequest{Parent: cryptoKeyName})
	if err != nil && status.Code(err) != codes.AlreadyExists {
		return fmt.Errorf("create crypto key version %s: %w", cryptoKeyName, err)
	}
	if err == nil {
		slog.InfoContext(ctx, "seeded crypto key version", "cryptoKey", cryptoKeyName)
	}
	return nil
}

type document struct {
	Projects map[string]project `yaml:"projects"`
}

type project struct {
	Locations map[string]location `yaml:"locations"`
}

type location struct {
	KeyRings map[string]keyRing `yaml:"keyRings"`
}

type keyRing struct {
	CryptoKeys map[string]CryptoKeySeed `yaml:"cryptoKeys"`
}

// CryptoKeySeed defines the subset of fields supported in seed files.
type CryptoKeySeed struct {
	Purpose  string            `yaml:"purpose"`
	Labels   map[string]string `yaml:"labels"`
	Versions []versionSeed     `yaml:"versions"`
}

type versionSeed struct {
	ID    string `yaml:"id"`
	State string `yaml:"state"`
}

func ensureYAML(path string) error {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return nil
	default:
		return fmt.Errorf("seed file %q must be a YAML document (.yaml or .yml)", path)
	}
}
