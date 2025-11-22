package grpcserver

import (
	"context"
	"fmt"

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
	res, err := h.svc.CreateKeyRing(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("create key ring: %w", err)
	}
	return res, nil
}

func (h *handler) GetKeyRing(ctx context.Context, req *kmspb.GetKeyRingRequest) (*kmspb.KeyRing, error) {
	res, err := h.svc.GetKeyRing(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("get key ring: %w", err)
	}
	return res, nil
}

func (h *handler) ListKeyRings(ctx context.Context, req *kmspb.ListKeyRingsRequest) (*kmspb.ListKeyRingsResponse, error) {
	res, err := h.svc.ListKeyRings(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("list key rings: %w", err)
	}
	return res, nil
}

func (h *handler) CreateCryptoKey(ctx context.Context, req *kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	res, err := h.svc.CreateCryptoKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("create crypto key: %w", err)
	}
	return res, nil
}

func (h *handler) GetCryptoKey(ctx context.Context, req *kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
	res, err := h.svc.GetCryptoKey(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("get crypto key: %w", err)
	}
	return res, nil
}

func (h *handler) ListCryptoKeys(ctx context.Context, req *kmspb.ListCryptoKeysRequest) (*kmspb.ListCryptoKeysResponse, error) {
	res, err := h.svc.ListCryptoKeys(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("list crypto keys: %w", err)
	}
	return res, nil
}

func (h *handler) CreateCryptoKeyVersion(ctx context.Context, req *kmspb.CreateCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	res, err := h.svc.CreateCryptoKeyVersion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("create crypto key version: %w", err)
	}
	return res, nil
}

func (h *handler) GetCryptoKeyVersion(ctx context.Context, req *kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
	res, err := h.svc.GetCryptoKeyVersion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("get crypto key version: %w", err)
	}
	return res, nil
}

func (h *handler) ListCryptoKeyVersions(ctx context.Context, req *kmspb.ListCryptoKeyVersionsRequest) (*kmspb.ListCryptoKeyVersionsResponse, error) {
	res, err := h.svc.ListCryptoKeyVersions(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("list crypto key versions: %w", err)
	}
	return res, nil
}

func (h *handler) UpdateCryptoKeyPrimaryVersion(ctx context.Context, req *kmspb.UpdateCryptoKeyPrimaryVersionRequest) (*kmspb.CryptoKey, error) {
	res, err := h.svc.UpdateCryptoKeyPrimaryVersion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("update primary version: %w", err)
	}
	return res, nil
}

func (h *handler) Encrypt(ctx context.Context, req *kmspb.EncryptRequest) (*kmspb.EncryptResponse, error) {
	res, err := h.svc.Encrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	return res, nil
}

func (h *handler) Decrypt(ctx context.Context, req *kmspb.DecryptRequest) (*kmspb.DecryptResponse, error) {
	res, err := h.svc.Decrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return res, nil
}
