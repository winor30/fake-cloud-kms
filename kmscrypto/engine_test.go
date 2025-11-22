package kmscrypto

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestTinkEngineRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	engine := NewTinkEngine()

	material, err := engine.GenerateKeyMaterial(ctx)
	if err != nil {
		t.Fatalf("generate key material: %v", err)
	}

	tests := []struct {
		name string
		aad  []byte
		want []byte
		err  bool
	}{
		{name: "success", aad: []byte("aad"), want: []byte("secure payload")},
		{name: "aad mismatch", aad: []byte("bad-aad"), want: nil, err: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := engine.Encrypt(ctx, material, []byte("secure payload"), []byte("aad"))
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			got, err := engine.Decrypt(ctx, material, ciphertext, tt.aad)
			if tt.err {
				if err == nil {
					t.Fatalf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("plaintext mismatch: got %q want %q", got, tt.want)
			}
		})
	}
}

func TestTinkEngineContextCancellation(t *testing.T) {
	t.Parallel()
	engine := NewTinkEngine()

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := engine.GenerateKeyMaterial(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("GenerateKeyMaterial: expected context cancellation, got %v", err)
	}

	material, err := engine.GenerateKeyMaterial(context.Background())
	if err != nil {
		t.Fatalf("generate key material: %v", err)
	}

	if _, err := engine.Encrypt(cancelled, material, []byte("data"), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Encrypt: expected context cancellation, got %v", err)
	}
	if _, err := engine.Decrypt(cancelled, material, []byte("ciphertext"), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Decrypt: expected context cancellation, got %v", err)
	}
}
