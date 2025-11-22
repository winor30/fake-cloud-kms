package names

import (
	"fmt"
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

// ParseLocation parses projects/<project>/locations/<location>.
func ParseLocation(name string) (Location, error) {
	parts := strings.Split(name, "/")
	if len(parts) != 4 || parts[0] != "projects" || parts[2] != "locations" {
		return Location{}, fmt.Errorf("invalid location name %q", name)
	}
	if parts[1] == "" || parts[3] == "" {
		return Location{}, fmt.Errorf("location components must be non-empty: %q", name)
	}
	return Location{Project: parts[1], Location: parts[3]}, nil
}

// ParseKeyRing parses projects/<project>/locations/<location>/keyRings/<keyRing>.
func ParseKeyRing(name string) (KeyRing, error) {
	parts := strings.Split(name, "/")
	if len(parts) != 6 || parts[0] != "projects" || parts[2] != "locations" || parts[4] != "keyRings" {
		return KeyRing{}, fmt.Errorf("invalid key ring name %q", name)
	}
	if parts[1] == "" || parts[3] == "" || parts[5] == "" {
		return KeyRing{}, fmt.Errorf("key ring components must be non-empty: %q", name)
	}
	return KeyRing{Location: Location{Project: parts[1], Location: parts[3]}, KeyRing: parts[5]}, nil
}

// ParseCryptoKey parses projects/<project>/locations/<location>/keyRings/<keyRing>/cryptoKeys/<cryptoKey>.
func ParseCryptoKey(name string) (CryptoKey, error) {
	parts := strings.Split(name, "/")
	if len(parts) != 8 || parts[0] != "projects" || parts[2] != "locations" || parts[4] != "keyRings" || parts[6] != "cryptoKeys" {
		return CryptoKey{}, fmt.Errorf("invalid crypto key name %q", name)
	}
	if parts[1] == "" || parts[3] == "" || parts[5] == "" || parts[7] == "" {
		return CryptoKey{}, fmt.Errorf("crypto key components must be non-empty: %q", name)
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
	for _, idx := range []int{1, 3, 5, 7, 9} {
		if parts[idx] == "" {
			return CryptoKeyVersion{}, fmt.Errorf("crypto key version components must be non-empty: %q", name)
		}
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
