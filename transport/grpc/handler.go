package grpcserver

import (
	"context"

	"cloud.google.com/go/kms/apiv1/kmspb"

	"github.com/winor30/fake-cloud-kms/service"
)

// handler adapts KMSService to the gRPC server interface.
type handler struct {
	kmspb.UnimplementedKeyManagementServiceServer
	svc service.KMSService
}

func newHandler(svc service.KMSService) *handler {
	return &handler{svc: svc}
}

func (h *handler) CreateKeyRing(ctx context.Context, req *kmspb.CreateKeyRingRequest) (*kmspb.KeyRing, error) {
	return h.svc.CreateKeyRing(ctx, req)
}

func (h *handler) GetKeyRing(ctx context.Context, req *kmspb.GetKeyRingRequest) (*kmspb.KeyRing, error) {
	return h.svc.GetKeyRing(ctx, req)
}

func (h *handler) ListKeyRings(ctx context.Context, req *kmspb.ListKeyRingsRequest) (*kmspb.ListKeyRingsResponse, error) {
	return h.svc.ListKeyRings(ctx, req)
}

func (h *handler) CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	return h.svc.CreateCryptoKey(ctx, req)
}

func (h *handler) GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	return h.svc.GetCryptoKey(ctx, req)
}

func (h *handler) ListCryptoKeys(ctx context.Context, req *kmspb.ListCryptoKeysRequest) (*kmspb.ListCryptoKeysResponse, error) {
	return h.svc.ListCryptoKeys(ctx, req)
}

func (h *handler) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	return h.svc.CreateCryptoKeyVersion(ctx, req)
}

func (h *handler) GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	return h.svc.GetCryptoKeyVersion(ctx, req)
}

func (h *handler) ListCryptoKeyVersions(ctx context.Context, req *kmspb.ListCryptoKeyVersionsRequest) (*kmspb.ListCryptoKeyVersionsResponse, error) {
	return h.svc.ListCryptoKeyVersions(ctx, req)
}

func (h *handler) UpdateCryptoKeyPrimaryVersion(ctx context.Context, req *kmspb.UpdateCryptoKeyPrimaryVersionRequest) (*kmspb.CryptoKey, error) {
	return h.svc.UpdateCryptoKeyPrimaryVersion(ctx, req)
}

func (h *handler) Encrypt(ctx context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	return h.svc.Encrypt(ctx, req)
}

func (h *handler) Decrypt(ctx context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	return h.svc.Decrypt(ctx, req)
}
