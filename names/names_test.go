package names_test

import (
	"testing"

	"github.com/winor30/fake-cloud-kms/names"
)

func TestParseAndFormat(t *testing.T) {
	loc, err := names.ParseLocation("projects/demo/locations/global")
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	if got := loc.ParentName(); got != "projects/demo/locations/global" {
		t.Fatalf("parent mismatch: %s", got)
	}

	kr, err := names.ParseKeyRing("projects/demo/locations/global/keyRings/app")
	if err != nil {
		t.Fatalf("parse key ring: %v", err)
	}
	if got := kr.ResourceName(); got != "projects/demo/locations/global/keyRings/app" {
		t.Fatalf("key ring resource mismatch: %s", got)
	}

	ck, err := names.ParseCryptoKey("projects/demo/locations/global/keyRings/app/cryptoKeys/pair")
	if err != nil {
		t.Fatalf("parse crypto key: %v", err)
	}
	if got := ck.ResourceName(); got != "projects/demo/locations/global/keyRings/app/cryptoKeys/pair" {
		t.Fatalf("crypto key resource mismatch: %s", got)
	}

	ver, err := names.ParseCryptoKeyVersion("projects/demo/locations/global/keyRings/app/cryptoKeys/pair/cryptoKeyVersions/1")
	if err != nil {
		t.Fatalf("parse version: %v", err)
	}
	if got := ver.ResourceName(); got != "projects/demo/locations/global/keyRings/app/cryptoKeys/pair/cryptoKeyVersions/1" {
		t.Fatalf("version resource mismatch: %s", got)
	}
}
