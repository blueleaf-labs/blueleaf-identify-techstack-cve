import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync } from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const cliPath = path.join(projectRoot, "dist", "cli", "bin.js");
const apiPath = path.join(projectRoot, "dist", "api", "main.js");

async function reservePort() {
  const listener = net.createServer();
  listener.listen(0, "127.0.0.1");
  await once(listener, "listening");
  const address = listener.address();
  await new Promise((resolve, reject) =>
    listener.close((error) => (error ? reject(error) : resolve())),
  );
  if (!address || typeof address === "string") throw new Error("No local TCP port.");
  return address.port;
}

function runCli(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cliPath, ...args], {
      cwd: projectRoot,
      stdio: ["ignore", "pipe", "ignore"],
    });
    let output = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => {
      output += chunk;
    });
    child.once("error", () => reject(new Error("Compiled CLI did not start.")));
    child.once("exit", (code) =>
      code === 0
        ? resolve(output)
        : reject(new Error("Compiled CLI did not exit cleanly.")),
    );
  });
}

async function waitForApi(port, token, child) {
  const deadline = Date.now() + 10_000;
  for (;;) {
    if (child.exitCode !== null) throw new Error("Compiled API exited during startup.");
    try {
      const health = await fetch(`http://127.0.0.1:${port}/health`, {
        headers: { authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(1_000),
      });
      const readiness = await fetch(`http://127.0.0.1:${port}/ready`, {
        headers: { authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(1_000),
      });
      const healthBody = await health.json();
      const readinessBody = await readiness.json();
      if (
        health.status === 200 &&
        readiness.status === 200 &&
        healthBody.status === "ok" &&
        readinessBody.status === "ready"
      )
        return;
      throw new Error("Compiled API health response was invalid.");
    } catch (error) {
      if (
        error instanceof Error &&
        error.message === "Compiled API health response was invalid."
      )
        throw error;
      if (Date.now() >= deadline) throw new Error("Compiled API did not become ready.");
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }
}

async function main() {
  if (!existsSync(cliPath) || !existsSync(apiPath))
    throw new Error("Build the package before running release smoke checks.");
  const help = await runCli(["--help"]);
  const version = await runCli(["--version"]);
  if (!help.includes("blueleaf scan <http-or-https-url>") || version.trim() !== "0.1.0")
    throw new Error("Compiled CLI smoke checks failed.");

  const port = await reservePort();
  const token = randomBytes(32).toString("base64url");
  const childEnv = Object.fromEntries(
    Object.entries(process.env).filter(
      ([name]) => !["BLUELEAF_API_KEYS_JSON", "BLUELEAF_NVD_API_KEY"].includes(name),
    ),
  );
  const child = spawn(process.execPath, [apiPath], {
    cwd: projectRoot,
    env: {
      ...childEnv,
      BLUELEAF_API_HOST: "127.0.0.1",
      BLUELEAF_API_PORT: String(port),
      BLUELEAF_API_KEYS_JSON: JSON.stringify([{ identity: "release-smoke", token }]),
    },
    stdio: "ignore",
  });
  try {
    await waitForApi(port, token, child);
    child.kill("SIGTERM");
    let shutdownTimer;
    const exit = await Promise.race([
      once(child, "exit"),
      new Promise((_, reject) => {
        shutdownTimer = setTimeout(
          () => reject(new Error("Compiled API did not shut down in time.")),
          7_000,
        );
      }),
    ]).finally(() => clearTimeout(shutdownTimer));
    // Windows child-process termination reports the signal rather than a POSIX exit code.
    if (process.platform !== "win32" && exit[0] !== 0)
      throw new Error(
        `Compiled API did not shut down cleanly (code ${exit[0]}, signal ${exit[1]}).`,
      );
  } finally {
    if (child.exitCode === null) child.kill("SIGKILL");
  }
  process.stdout.write(
    process.platform === "win32"
      ? "Built CLI and API health/readiness passed; API shutdown behavior is covered by integration tests.\n"
      : "Built CLI and API health/readiness/graceful shutdown passed.\n",
  );
}

main().catch((error) => {
  const detail = error instanceof Error ? error.message : "Unexpected failure.";
  process.stderr.write(`Built artifact smoke verification failed: ${detail}\n`);
  process.exitCode = 1;
});
