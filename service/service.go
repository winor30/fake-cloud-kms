package service

import (
	"context"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/winor30/fake-cloud-kms/crc"
	"github.com/winor30/fake-cloud-kms/kmscrypto"
	"github.com/winor30/fake-cloud-kms/names"
	"github.com/winor30/fake-cloud-kms/store"
)

// KMSService defines transport-agnostic business operations.
type KMSService interface {
	CreateKeyRing(ctx context.Context, req *kmspb.CreateKeyRingRequest) (*kmspb.KeyRing, error)
	GetKeyRing(ctx context.Context, req *kmspb.GetKeyRingRequest) (*kmspb.KeyRing, error)
	ListKeyRings(ctx context.Context, req *kmspb.ListKeyRingsRequest) (*kmspb.ListKeyRingsResponse, error)

	CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error)
	GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error)
	ListCryptoKeys(ctx context.Context, req *kmspb.ListCryptoKeysRequest) (*kmspb.ListCryptoKeysResponse, error)

	CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error)
	GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error)
	ListCryptoKeyVersions(ctx context.Context, req *kmspb.ListCryptoKeyVersionsRequest) (*kmspb.ListCryptoKeyVersionsResponse, error)

	UpdateCryptoKeyPrimaryVersion(ctx context.Context, req *kmspb.UpdateCryptoKeyPrimaryVersionRequest) (*kmspb.CryptoKey, error)
	Encrypt(ctx context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error)
	Decrypt(ctx context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error)
}

// service implements the KMS operations against the provided store and crypto engine.
type service struct {
	store  store.Store
	engine kmscrypto.Engine
}

var _ KMSService = (*service)(nil)

// New constructs a service.
func New(store store.Store, engine kmscrypto.Engine) *service {
	return &service{store: store, engine: engine}
}

func (s *service) CreateKeyRing(ctx context.Context, req *kmspb.CreateKeyRingRequest) (*kmspb.KeyRing, error) {
	parent, err := names.ParseLocation(req.GetParent())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid parent: %v", err)
	}

	if req.GetKeyRingId() == "" {
		return nil, status.Error(codes.InvalidArgument, "key_ring_id is required")
	}

	name := fmt.Sprintf("%s/keyRings/%s", parent.ParentName(), req.GetKeyRingId())
	kr := &kmspb.KeyRing{
		Name:       name,
		CreateTime: timestamppb.Now(),
	}

	if err := s.store.CreateKeyRing(ctx, kr); err != nil {
		return nil, err
	}
	return kr, nil
}

func (s *service) GetKeyRing(ctx context.Context, req *kmspb.GetKeyRingRequest) (*kmspb.KeyRing, error) {
	if _, err := names.ParseKeyRing(req.GetName()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid name: %v", err)
	}
	kr, err := s.store.GetKeyRing(ctx, req.GetName())
	if err != nil {
		return nil, err
	}
	return kr, nil
}

func (s *service) ListKeyRings(ctx context.Context, req *kmspb.ListKeyRingsRequest) (*kmspb.ListKeyRingsResponse, error) {
	parent, err := names.ParseLocation(req.GetParent())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid parent: %v", err)
	}

	if req.GetPageToken() != "" {
		return nil, status.Error(codes.Unimplemented, "pagination is not supported")
	}

	items, err := s.store.ListKeyRings(ctx, parent.ParentName())
	if err != nil {
		return nil, err
	}
	return &kmspb.ListKeyRingsResponse{KeyRings: items}, nil
}

func (s *service) CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	keyRing, err := names.ParseKeyRing(req.GetParent())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid parent: %v", err)
	}

	if req.GetCryptoKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "crypto_key_id is required")
	}

	if req.GetCryptoKey() == nil {
		return nil, status.Error(codes.InvalidArgument, "crypto_key is required")
	}

	if req.GetCryptoKey().GetPurpose() != kmspb.CryptoKey_ENCRYPT_DECRYPT {
		return nil, status.Error(codes.InvalidArgument, "only ENCRYPT_DECRYPT purpose is supported")
	}

	cryptoKeyName := fmt.Sprintf("%s/cryptoKeys/%s", keyRing.ResourceName(), req.GetCryptoKeyId())
	primaryVersionName := names.FormatCryptoKeyVersion(cryptoKeyName, "1")
	material, err := s.engine.GenerateKeyMaterial(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate key material: %v", err)
	}

	version := &kmspb.CryptoKeyVersion{
		Name:            primaryVersionName,
		State:           kmspb.CryptoKeyVersion_ENABLED,
		ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		Algorithm:       kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
		CreateTime:      timestamppb.Now(),
	}

	ck := &kmspb.CryptoKey{
		Name:       cryptoKeyName,
		CreateTime: timestamppb.Now(),
		Labels:     mapsCopy(req.GetCryptoKey().GetLabels()),
		Purpose:    kmspb.CryptoKey_ENCRYPT_DECRYPT,
		VersionTemplate: &kmspb.CryptoKeyVersionTemplate{
			ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
			Algorithm:       kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
		},
		Primary: version,
	}

	if err := s.store.CreateCryptoKey(ctx, keyRing.ResourceName(), ck, version, material); err != nil {
		return nil, err
	}
	return ck, nil
}

func (s *service) GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	if _, err := names.ParseCryptoKey(req.GetName()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid name: %v", err)
	}
	ck, err := s.store.GetCryptoKey(ctx, req.GetName())
	if err != nil {
		return nil, err
	}
	return ck, nil
}

func (s *service) ListCryptoKeys(ctx context.Context, req *kmspb.ListCryptoKeysRequest) (*kmspb.ListCryptoKeysResponse, error) {
	if _, err := names.ParseKeyRing(req.GetParent()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid parent: %v", err)
	}

	if req.GetPageToken() != "" {
		return nil, status.Error(codes.Unimplemented, "pagination is not supported")
	}
	items, err := s.store.ListCryptoKeys(ctx, req.GetParent())
	if err != nil {
		return nil, err
	}
	return &kmspb.ListCryptoKeysResponse{CryptoKeys: items}, nil
}

func (s *service) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	cryptoKeyName := req.GetParent()
	if _, err := names.ParseCryptoKey(cryptoKeyName); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid parent: %v", err)
	}

	material, err := s.engine.GenerateKeyMaterial(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate key material: %v", err)
	}

	existing, err := s.store.ListCryptoKeyVersions(ctx, cryptoKeyName)
	if err != nil {
		return nil, err
	}

	nextID := nextVersionID(existing)
	versionName := names.FormatCryptoKeyVersion(cryptoKeyName, strconv.Itoa(nextID))
	version := &kmspb.CryptoKeyVersion{
		Name:            versionName,
		State:           kmspb.CryptoKeyVersion_ENABLED,
		Algorithm:       kmspb.CryptoKeyVersion_GOOGLE_SYMMETRIC_ENCRYPTION,
		ProtectionLevel: kmspb.ProtectionLevel_SOFTWARE,
		CreateTime:      timestamppb.Now(),
	}

	if err := s.store.CreateCryptoKeyVersion(ctx, cryptoKeyName, version, material); err != nil {
		return nil, err
	}
	return version, nil
}

func (s *service) GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	if _, err := names.ParseCryptoKeyVersion(req.GetName()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid name: %v", err)
	}
	version, _, err := s.store.GetCryptoKeyVersion(ctx, req.GetName())
	if err != nil {
		return nil, err
	}
	return version, nil
}

func (s *service) ListCryptoKeyVersions(ctx context.Context, req *kmspb.ListCryptoKeyVersionsRequest) (*kmspb.ListCryptoKeyVersionsResponse, error) {
	if _, err := names.ParseCryptoKey(req.GetParent()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid parent: %v", err)
	}

	if req.GetPageToken() != "" {
		return nil, status.Error(codes.Unimplemented, "pagination is not supported")
	}

	versions, err := s.store.ListCryptoKeyVersions(ctx, req.GetParent())
	if err != nil {
		return nil, err
	}
	return &kmspb.ListCryptoKeyVersionsResponse{CryptoKeyVersions: versions}, nil
}

func (s *service) UpdateCryptoKeyPrimaryVersion(ctx context.Context, req *kmspb.UpdateCryptoKeyPrimaryVersionRequest) (*kmspb.CryptoKey, error) {
	if _, err := names.ParseCryptoKey(req.GetName()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid name: %v", err)
	}

	if req.GetCryptoKeyVersionId() == "" {
		return nil, status.Error(codes.InvalidArgument, "crypto_key_version_id is required")
	}

	versionName := names.FormatCryptoKeyVersion(req.GetName(), req.GetCryptoKeyVersionId())
	ck, err := s.store.SetPrimaryVersion(ctx, req.GetName(), versionName)
	if err != nil {
		return nil, err
	}

	return ck, nil
}

func (s *service) Encrypt(ctx context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	if _, err := names.ParseCryptoKey(req.GetName()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid name: %v", err)
	}

	ck, err := s.store.GetCryptoKey(ctx, req.GetName())
	if err != nil {
		return nil, err
	}

	if ck.GetPrimary() == nil {
		return nil, status.Error(codes.FailedPrecondition, "crypto key has no primary version")
	}

	verifiedPlaintext, err := verifyChecksum(req.GetPlaintext(), req.GetPlaintextCrc32C())
	if err != nil {
		return nil, err
	}
	verifiedAAD, err := verifyChecksum(req.GetAdditionalAuthenticatedData(), req.GetAdditionalAuthenticatedDataCrc32C())
	if err != nil {
		return nil, err
	}

	versionName := ck.GetPrimary().GetName()
	version, material, err := s.store.GetCryptoKeyVersion(ctx, versionName)
	if err != nil {
		return nil, err
	}

	ciphertextOnly, err := s.engine.Encrypt(ctx, material, req.GetPlaintext(), req.GetAdditionalAuthenticatedData())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encrypt failed: %v", err)
	}

	ciphertext := wrapCiphertext(versionName, ciphertextOnly)
	checksum := crc.Compute(ciphertext)
	return &kmspb.EncryptResponse{
		Name:                    version.GetName(),
		Ciphertext:              ciphertext,
		CiphertextCrc32C:        wrapperspb.Int64(int64(checksum)),
		VerifiedPlaintextCrc32C: verifiedPlaintext,
		VerifiedAdditionalAuthenticatedDataCrc32C: verifiedAAD,
	}, nil
}

func (s *service) Decrypt(ctx context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	if _, err := names.ParseCryptoKey(req.GetName()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid name: %v", err)
	}

	ck, err := s.store.GetCryptoKey(ctx, req.GetName())
	if err != nil {
		return nil, err
	}

	if _, err := verifyChecksum(req.GetCiphertext(), req.GetCiphertextCrc32C()); err != nil {
		return nil, err
	}
	if _, err := verifyChecksum(req.GetAdditionalAuthenticatedData(), req.GetAdditionalAuthenticatedDataCrc32C()); err != nil {
		return nil, err
	}

	versionName, ciphertextOnly, err := unwrapCiphertext(req.GetCiphertext())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid ciphertext payload: %v", err)
	}

	versionInfo, material, err := s.store.GetCryptoKeyVersion(ctx, versionName)
	if err != nil {
		return nil, err
	}

	versionResource, err := names.ParseCryptoKeyVersion(versionName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "stored version has invalid name: %v", err)
	}
	if versionResource.CryptoKey.ResourceName() != req.GetName() {
		return nil, status.Error(codes.FailedPrecondition, "ciphertext was encrypted with a different crypto key")
	}

	plaintext, err := s.engine.Decrypt(ctx, material, ciphertextOnly, req.GetAdditionalAuthenticatedData())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "decrypt failed: %v", err)
	}

	checksum := crc.Compute(plaintext)
	usedPrimary := ck.GetPrimary() != nil && ck.GetPrimary().GetName() == versionInfo.GetName()
	return &kmspb.DecryptResponse{
		Plaintext:       plaintext,
		PlaintextCrc32C: wrapperspb.Int64(int64(checksum)),
		UsedPrimary:     usedPrimary,
	}, nil
}

func verifyChecksum(data []byte, checksum *wrapperspb.Int64Value) (bool, error) {
	if checksum == nil || checksum.GetValue() == 0 {
		return false, nil
	}
	computed := int64(crc.Compute(data))
	if checksum.GetValue() != computed {
		return false, status.Error(codes.InvalidArgument, "checksum mismatch")
	}
	return true, nil
}

// wrapCiphertext encodes the version-qualified ciphertext payload.
// It returns a byte array with the following layout:
// <length of versionName> <versionName> <ciphertext>
func wrapCiphertext(versionName string, ciphertext []byte) []byte {
	nameBytes := []byte(versionName)
	buf := make([]byte, 2+len(nameBytes)+len(ciphertext))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(nameBytes)))
	copy(buf[2:], nameBytes)
	copy(buf[2+len(nameBytes):], ciphertext)
	return buf
}

// unwrapCiphertext decodes a payload produced by wrapCiphertext.
func unwrapCiphertext(payload []byte) (string, []byte, error) {
	if len(payload) < 2 {
		return "", nil, fmt.Errorf("payload too short")
	}
	nameLen := int(binary.BigEndian.Uint16(payload[:2]))
	if len(payload) < 2+nameLen {
		return "", nil, fmt.Errorf("payload missing ciphertext body")
	}
	name := string(payload[2 : 2+nameLen])
	ciphertext := append([]byte(nil), payload[2+nameLen:]...)
	return name, ciphertext, nil
}

func nextVersionID(existing []*kmspb.CryptoKeyVersion) int {
	maxID := 0
	for _, v := range existing {
		_, suffix, ok := strings.Cut(v.GetName(), "/cryptoKeyVersions/")
		if !ok {
			continue
		}
		if parsed, err := strconv.Atoi(suffix); err == nil && parsed > maxID {
			maxID = parsed
		}
	}
	return maxID + 1
}

func mapsCopy(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
