#!/usr/bin/env node
// Nebula relay server — receives proof data from the browser extension,
// shells out to `stellar contract invoke` to submit the withdrawal on-chain.
//
// Usage:
//   node server.js
//   PORT=3000 STELLAR_ACCOUNT=quantum-deployer node server.js

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import http from "node:http";

const execFileAsync = promisify(execFile);

const PORT = process.env.PORT || 3000;
const STELLAR_ACCOUNT = process.env.STELLAR_ACCOUNT || "quantum-deployer";
const WALLET_CONTRACT =
  process.env.WALLET_CONTRACT ||
  "CCQ4R5FTHPDBGPMYEWEDRKZMHWHYN4QB26DRTZCM4MICARWNLJK56Q6B";
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*"; // tighten in prod

async function stellarInvoke(
  proofBytes,
  publicValues,
  destination,
  amountStroops,
) {
  const { stdout, stderr } = await execFileAsync(
    "stellar",
    [
      "contract",
      "invoke",
      "--id",
      WALLET_CONTRACT,
      "--source-account",
      STELLAR_ACCOUNT,
      "--network",
      "testnet",
      "--",
      "withdraw",
      "--proof_bytes",
      proofBytes,
      "--public_values",
      publicValues,
      "--destination",
      destination,
      "--amount",
      String(amountStroops),
    ],
    { timeout: 120_000 },
  );

  // stellar contract invoke prints the tx hash (or return value) to stdout
  const txHash = stdout.trim().replace(/^"|"$/g, "");
  return { txHash, stderr: stderr.trim() };
}

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function json(res, status, body) {
  cors(res);
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => {
      data += chunk;
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(new Error("invalid JSON"));
      }
    });
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method === "OPTIONS") {
    cors(res);
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.method === "POST" && req.url === "/withdraw") {
    let body;
    try {
      body = await readBody(req);
    } catch (e) {
      return json(res, 400, { error: e.message });
    }

    const { proof_bytes, public_values, destination, amount_stroops } = body;
    if (
      !proof_bytes ||
      !public_values ||
      !destination ||
      amount_stroops == null
    ) {
      return json(res, 400, {
        error:
          "missing fields: proof_bytes, public_values, destination, amount_stroops",
      });
    }

    console.log(
      `[relay] withdraw → dest=${destination} amount=${amount_stroops}`,
    );
    console.log(`[relay] proof_bytes length: ${proof_bytes.length / 2} bytes`);

    try {
      const { txHash, stderr } = await stellarInvoke(
        proof_bytes,
        public_values,
        destination,
        amount_stroops,
      );
      if (stderr) console.log(`[relay] stellar stderr: ${stderr}`);
      console.log(`[relay] tx hash: ${txHash}`);
      return json(res, 200, { tx_hash: txHash });
    } catch (e) {
      const msg = e.stderr || e.stdout || e.message || String(e);
      console.error(`[relay] error: ${msg}`);
      return json(res, 500, { error: msg });
    }
  }

  if (req.method === "GET" && req.url === "/health") {
    return json(res, 200, { ok: true });
  }

  json(res, 404, { error: "not found" });
});

server.listen(PORT, () => {
  console.log(`Nebula relay server listening on http://localhost:${PORT}`);
  console.log(`  STELLAR_ACCOUNT = ${STELLAR_ACCOUNT}`);
  console.log(`  WALLET_CONTRACT = ${WALLET_CONTRACT}`);
});
