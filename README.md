# Fake Cloud KMS (Unofficial Emulator)

An unofficial gRPC emulator for Google Cloud KMS aimed at local development and CI. It is not an official Google product—never load production secrets.

## Quick Start
- Go 1.25+ required.
- Run:
```bash
go run ./cmd/fake-cloud-kms \
  --grpc-listen-addr 127.0.0.1:9010 \
  --store memory \
  --log-level info \
  --seed-file testdata/seeds.yaml   # optional, YAML only
```
- Point clients at the gRPC address (TLS is disabled). With the Go client library, pass `option.WithEndpoint(addr)` and `option.WithoutAuthentication()`.

## Docker Image
- Prebuilt image on Docker Hub: [winor30/fake-cloud-kms](https://hub.docker.com/repository/docker/winor30/fake-cloud-kms/general).
- Run the emulator in a container (defaults to `--grpc-listen-addr 0.0.0.0:9010` from the entrypoint):
```bash
docker run --rm -p 9010:9010 winor30/fake-cloud-kms:latest
```
- To load seeds, mount them into the container and pass the file path:
```bash
docker run --rm -p 9010:9010 \
  -v "$(pwd)/testdata/seeds.yaml:/data/seeds.yaml:ro" \
  winor30/fake-cloud-kms:latest \
  --seed-file /data/seeds.yaml
```

## Supported Surface
- Resource RPCs: Create/Get/List KeyRing, CryptoKey, CryptoKeyVersion; UpdateCryptoKeyPrimaryVersion. `CreateCryptoKey` auto-creates version `1` (ENABLED); use `CreateCryptoKeyVersion` for more. Pagination returns `Unimplemented`.
- Crypto: Encrypt/Decrypt using `GOOGLE_SYMMETRIC_ENCRYPTION` (`ProtectionLevel_SOFTWARE`) with CRC32C verification for plaintext/ciphertext/AAD and `UsedPrimary` reporting.
- Storage/config: in-memory store only (state is ephemeral). Flags: `--grpc-listen-addr` (default `127.0.0.1:9010`), `--store` (`memory` only), `--seed-file` (YAML), `--log-level` (`debug|info|warn|error`, default `info`).

## Limitations
- Destroy/Restore and state transitions beyond `ENABLED` are not implemented.
- Other key purposes/algorithms/protection levels (MAC, asymmetric, raw encrypt, HSM/FIPS) are unsupported.
- No pagination and no TLS termination.

## In-Process Usage (Go)
```go
ctx := context.Background()
server, err := emulator.Start(ctx, emulator.Options{})
if err != nil {
	log.Fatal(err)
}
defer server.Stop(ctx)
fmt.Println("addr:", server.Addr)
```

## Seeding (YAML)
```yaml
projects:
  demo:
    locations:
      global:
        keyRings:
          app-ring:
            cryptoKeys:
              app-key:
                purpose: ENCRYPT_DECRYPT
                labels:
                  env: dev
                versions:
                  - {}   # creates version 1
                  - {}   # creates version 2
```

## Samples
- `clients/typescript`: spins up the emulator via Testcontainers and exercises Encrypt/Decrypt through the official `@google-cloud/kms` client. Run with `pnpm start` or build the provided Docker image.

## Development
- `go build ./cmd/fake-cloud-kms`
- `go test ./...`
- `golangci-lint run ./...`
- `make fmt vet lint test build` to mirror CI.
