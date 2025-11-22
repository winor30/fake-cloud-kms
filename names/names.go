package names

import (
	"fmt"
	"regexp"
	"strings"
)

// Location identifies a Cloud KMS location resource.
type Location struct {
	Project  string
	Location string
}

// KeyRing identifies a key ring resource.
type KeyRing struct {
	Location
	KeyRing string
}

// CryptoKey identifies a crypto key resource.
type CryptoKey struct {
	KeyRing
	CryptoKey string
}

// CryptoKeyVersion identifies a crypto key version resource.
type CryptoKeyVersion struct {
	CryptoKey
	Version string
}

var (
	idPattern      = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,63}$`)
	versionPattern = regexp.MustCompile(`^[0-9]+$`)
)

// ParseLocation parses projects/<project>/locations/<location>.
func ParseLocation(name string) (Location, error) {
	parts := strings.Split(name, "/")
	if len(parts) != 4 || parts[0] != "projects" || parts[2] != "locations" {
		return Location{}, fmt.Errorf("invalid location name %q", name)
	}
	if err := validateID("project", parts[1]); err != nil {
		return Location{}, fmt.Errorf("invalid location name %q: %w", name, err)
	}
	if err := validateID("location", parts[3]); err != nil {
		return Location{}, fmt.Errorf("invalid location name %q: %w", name, err)
	}
	return Location{Project: parts[1], Location: parts[3]}, nil
}

// ParseKeyRing parses projects/<project>/locations/<location>/keyRings/<keyRing>.
func ParseKeyRing(name string) (KeyRing, error) {
	parts := strings.Split(name, "/")
	if len(parts) != 6 || parts[0] != "projects" || parts[2] != "locations" || parts[4] != "keyRings" {
		return KeyRing{}, fmt.Errorf("invalid key ring name %q", name)
	}
	for _, label := range []struct {
		kind string
		val  string
	}{
		{"project", parts[1]},
		{"location", parts[3]},
		{"key_ring", parts[5]},
	} {
		if err := validateID(label.kind, label.val); err != nil {
			return KeyRing{}, fmt.Errorf("invalid key ring name %q: %w", name, err)
		}
	}
	return KeyRing{Location: Location{Project: parts[1], Location: parts[3]}, KeyRing: parts[5]}, nil
}

// ParseCryptoKey parses projects/<project>/locations/<location>/keyRings/<keyRing>/cryptoKeys/<cryptoKey>.
func ParseCryptoKey(name string) (CryptoKey, error) {
	parts := strings.Split(name, "/")
	if len(parts) != 8 || parts[0] != "projects" || parts[2] != "locations" || parts[4] != "keyRings" || parts[6] != "cryptoKeys" {
		return CryptoKey{}, fmt.Errorf("invalid crypto key name %q", name)
	}
	for _, label := range []struct {
		kind string
		val  string
	}{
		{"project", parts[1]},
		{"location", parts[3]},
		{"key_ring", parts[5]},
		{"crypto_key", parts[7]},
	} {
		if err := validateID(label.kind, label.val); err != nil {
			return CryptoKey{}, fmt.Errorf("invalid crypto key name %q: %w", name, err)
		}
	}
	return CryptoKey{
		KeyRing:   KeyRing{Location: Location{Project: parts[1], Location: parts[3]}, KeyRing: parts[5]},
		CryptoKey: parts[7],
	}, nil
}

// ParseCryptoKeyVersion parses projects/<project>/locations/<location>/keyRings/<keyRing>/cryptoKeys/<cryptoKey>/cryptoKeyVersions/<version>.
func ParseCryptoKeyVersion(name string) (CryptoKeyVersion, error) {
	parts := strings.Split(name, "/")
	if len(parts) != 10 || parts[0] != "projects" || parts[2] != "locations" || parts[4] != "keyRings" || parts[6] != "cryptoKeys" || parts[8] != "cryptoKeyVersions" {
		return CryptoKeyVersion{}, fmt.Errorf("invalid crypto key version name %q", name)
	}
	for _, label := range []struct {
		kind string
		val  string
	}{
		{"project", parts[1]},
		{"location", parts[3]},
		{"key_ring", parts[5]},
		{"crypto_key", parts[7]},
	} {
		if err := validateID(label.kind, label.val); err != nil {
			return CryptoKeyVersion{}, fmt.Errorf("invalid crypto key version name %q: %w", name, err)
		}
	}
	if err := validateVersionID(parts[9]); err != nil {
		return CryptoKeyVersion{}, fmt.Errorf("invalid crypto key version name %q: %w", name, err)
	}
	return CryptoKeyVersion{
		CryptoKey: CryptoKey{
			KeyRing:   KeyRing{Location: Location{Project: parts[1], Location: parts[3]}, KeyRing: parts[5]},
			CryptoKey: parts[7],
		},
		Version: parts[9],
	}, nil
}

// Format helpers.
func (l Location) ParentName() string {
	return fmt.Sprintf("projects/%s/locations/%s", l.Project, l.Location)
}

func (k KeyRing) ResourceName() string {
	return fmt.Sprintf("%s/keyRings/%s", k.ParentName(), k.KeyRing)
}

func (k CryptoKey) ResourceName() string {
	return fmt.Sprintf("%s/cryptoKeys/%s", k.KeyRing.ResourceName(), k.CryptoKey)
}

func (v CryptoKeyVersion) ResourceName() string {
	return fmt.Sprintf("%s/cryptoKeyVersions/%s", v.CryptoKey.ResourceName(), v.Version)
}

// FormatCryptoKeyVersion builds a crypto key version resource name.
func FormatCryptoKeyVersion(cryptoKeyName, version string) string {
	return fmt.Sprintf("%s/cryptoKeyVersions/%s", cryptoKeyName, version)
}

func validateID(kind, value string) error {
	if value == "" {
		return fmt.Errorf("%s must be non-empty", kind)
	}
	if !idPattern.MatchString(value) {
		return fmt.Errorf("%s must match %s", kind, idPattern.String())
	}
	return nil
}

func validateVersionID(value string) error {
	if value == "" {
		return fmt.Errorf("version must be non-empty")
	}
	if !versionPattern.MatchString(value) {
		return fmt.Errorf("version must match %s", versionPattern.String())
	}
	return nil
}
