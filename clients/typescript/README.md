# TypeScript Cloud KMS Client Sample

This directory contains a minimal TypeScript program that exercises the fake Cloud KMS emulator via the official `@google-cloud/kms` client library. It always starts the emulator via Testcontainers using the repository-root `Dockerfile`, then creates a key ring + crypto key, encrypts a short message, and immediately decrypts it to verify compatibility.

## Prerequisites
- Node.js 20+ (the Dockerfile uses the `node:22-slim` image)
- Docker (Testcontainers builds/runs the emulator image from the repository `Dockerfile`)

## Running locally
```bash
cd clients/typescript
npm install
npm start
```

Optional environment variables:
- `GOOGLE_CLOUD_PROJECT` (default `demo`)
- `KMS_LOCATION` (default `global`)
- `KMS_KEY_RING` (default `app-ring`)
- `KMS_CRYPTO_KEY` (default `app-key`)
- `KMS_PLAINTEXT` (default `Hello from TypeScript client!`)
- `KMS_AAD` (default `ts-client`)
  (the emulator host/port are managed by Testcontainers; no host override)

## Docker usage
The repository root contains a `Dockerfile` that builds this client into a runnable container. Example:
```bash
docker build -t kms-ts-client .
docker run --rm kms-ts-client
```

The container simply executes `node dist/index.js`, making it easy to run via Testcontainers or any CI pipeline.
