import { KeyManagementServiceClient } from "@google-cloud/kms";
import { status } from "@grpc/grpc-js";
import { grpc } from "google-gax";
import path from "node:path";
import { GenericContainer, Wait } from "testcontainers";

interface Config {
  projectId: string;
  locationId: string;
  keyRingId: string;
  cryptoKeyId: string;
  plaintext: string;
  aad: string;
}

function isAlreadyExists(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    (err as { code?: unknown }).code === status.ALREADY_EXISTS
  );
}

function loadConfig(): Config {
  return {
    projectId: process.env.GOOGLE_CLOUD_PROJECT ?? "demo",
    locationId: process.env.KMS_LOCATION ?? "global",
    keyRingId: process.env.KMS_KEY_RING ?? "app-ring",
    cryptoKeyId: process.env.KMS_CRYPTO_KEY ?? "app-key",
    plaintext: process.env.KMS_PLAINTEXT ?? "Hello from TypeScript client!",
    aad: process.env.KMS_AAD ?? "ts-client",
  };
}

function createClient(host: string, port: number): KeyManagementServiceClient {
  return new KeyManagementServiceClient({
    apiEndpoint: host,
    sslCreds: grpc.credentials.createInsecure(),
    fallback: false,
    port,
  });
}

async function startEmulator(): Promise<{
  host: string;
  port: number;
  stop: () => Promise<void>;
}> {
  const repoRoot = path.resolve(__dirname, "..", "..", "..");
  const builtContainer = await GenericContainer.fromDockerfile(
    repoRoot,
    "Dockerfile"
  ).build();
  const container = await builtContainer
    .withExposedPorts(9010)
    .withWaitStrategy(
      Wait.forLogMessage("Cloud KMS emulator listening").withStartupTimeout(
        45_000
      )
    )
    .start();

  return {
    host: container.getHost(),
    port: container.getMappedPort(9010),
    stop: async () => {
      await container.stop();
    },
  };
}

async function ensureKeyRing(
  client: KeyManagementServiceClient,
  parent: string,
  keyRingId: string
): Promise<void> {
  try {
    await client.createKeyRing({ parent, keyRingId, keyRing: {} });
    console.log(`created key ring ${parent}/keyRings/${keyRingId}`);
  } catch (err) {
    if (!isAlreadyExists(err)) {
      throw err;
    }
  }
}

async function ensureCryptoKey(
  client: KeyManagementServiceClient,
  keyRingName: string,
  cryptoKeyId: string
): Promise<void> {
  try {
    await client.createCryptoKey({
      parent: keyRingName,
      cryptoKeyId,
      cryptoKey: {
        purpose: "ENCRYPT_DECRYPT",
        versionTemplate: {
          algorithm: "GOOGLE_SYMMETRIC_ENCRYPTION",
          protectionLevel: "SOFTWARE",
        },
      },
    });
    console.log(`created crypto key ${keyRingName}/cryptoKeys/${cryptoKeyId}`);
  } catch (err) {
    if (!isAlreadyExists(err)) {
      throw err;
    }
  }
}

async function main(): Promise<void> {
  const cfg = loadConfig();
  const { host, port, stop } = await startEmulator();
  const client = createClient(host, port);
  try {
    const parent = `projects/${cfg.projectId}/locations/${cfg.locationId}`;
    const keyRingName = `${parent}/keyRings/${cfg.keyRingId}`;
    const cryptoKeyName = `${keyRingName}/cryptoKeys/${cfg.cryptoKeyId}`;

    await ensureKeyRing(client, parent, cfg.keyRingId);
    await ensureCryptoKey(client, keyRingName, cfg.cryptoKeyId);

    const plaintext = Buffer.from(cfg.plaintext, "utf8");
    const aad = Buffer.from(cfg.aad, "utf8");

    const [encryptResponse] = await client.encrypt({
      name: cryptoKeyName,
      plaintext,
      additionalAuthenticatedData: aad,
    });
    const ciphertext = encryptResponse.ciphertext ?? Buffer.alloc(0);
    console.log(
      "ciphertext (base64):",
      Buffer.from(ciphertext).toString("base64")
    );

    const [decryptResponse] = await client.decrypt({
      name: cryptoKeyName,
      ciphertext,
      additionalAuthenticatedData: aad,
    });

    const decrypted = Buffer.from(decryptResponse.plaintext ?? []);
    if (!decrypted.equals(plaintext)) {
      throw new Error("plaintext mismatch");
    }
    console.log("plaintext:", decrypted.toString("utf8"));
  } finally {
    await client.close();
    await stop();
  }
}

main().catch((err) => {
  console.error("TypeScript client failed:", err);
  process.exitCode = 1;
});
