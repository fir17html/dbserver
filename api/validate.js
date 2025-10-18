import fetch from "node-fetch";
import crypto from "crypto";

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const REPO_OWNER = process.env.REPO_OWNER || "fir17html";
const REPO_NAME = process.env.REPO_NAME || "dbnew";
const FILE_PATH = process.env.FILE_PATH || "xmddb.json";

const ACCESS_KEY = process.env.ACCESS_KEY || "#xmdnihbos";
const SHARED_SECRET = process.env.SHARED_SECRET || "#xmdnihbos";
const CACHE_TTL_MS = parseInt(process.env.CACHE_TTL_MS || "30000", 10);
const PAYLOAD_VALID_MS = parseInt(process.env.PAYLOAD_VALID_MS || "30000", 10);

let cache = {
  data: null,
  fetchedAt: 0
};

const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 30;
const rateMap = new Map();

// === Utility functions ===
function timingSafeEqualStr(a = "", b = "") {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  try {
    return crypto.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

function encryptPayload(payloadObj, secret) {
  const key = crypto.createHash("sha256").update(String(secret)).digest(); // 32 bytes
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const plaintext = JSON.stringify(payloadObj);
  let encrypted = cipher.update(plaintext, "utf8", "base64");
  encrypted += cipher.final("base64");
  return { data: encrypted, iv: iv.toString("base64") };
}

function hmacSignHex(data, secret) {
  // penting: encoding harus sama dengan di client (“utf8”)
  return crypto.createHmac("sha256", String(secret)).update(String(data), "utf8").digest("hex");
}

function isRateLimited(ip) {
  const now = Date.now();
  let entry = rateMap.get(ip);
  if (!entry || entry.windowStart + RATE_LIMIT_WINDOW_MS < now) {
    entry = { windowStart: now, count: 1 };
    rateMap.set(ip, entry);
    return false;
  }
  entry.count++;
  return entry.count > RATE_LIMIT_MAX;
}

async function fetchTokensFromGitHub() {
  const url = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/contents/${FILE_PATH}`;
  const res = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `token ${GITHUB_TOKEN}`,
      "User-Agent": "token-validator",
      Accept: "application/vnd.github.v3+json"
    }
  });

  if (!res.ok) throw new Error(`GitHub API error ${res.status}`);

  const json = await res.json();
  const contentStr = Buffer.from(json.content, "base64").toString("utf8");
  const parsed = JSON.parse(contentStr);
  if (!parsed || !Array.isArray(parsed.tokens)) throw new Error("Invalid JSON format");

  cache.data = parsed;
  cache.fetchedAt = Date.now();
  return parsed;
}

// === API handler ===
export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Apa lu liat liat pantek. by @KyzzexX" });
  }

  const now = Date.now();
  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress || "unknown";
  if (isRateLimited(ip)) return res.status(429).json({ error: "Too many requests" });

  const apiKey = req.headers["x-api-key"] || "";
  if (!timingSafeEqualStr(apiKey, ACCESS_KEY)) return res.status(401).json({ error: "Unauthorized" });

  const { token } = req.body || {};
  if (!token) return res.status(400).json({ valid: false, error: "Missing token" });

  try {
    if (!cache.data || now - cache.fetchedAt > CACHE_TTL_MS) {
      await fetchTokensFromGitHub();
    }

    const tokens = cache.data.tokens;
    const isValid = Array.isArray(tokens) && tokens.includes(token);

    const payload = {
      valid: !!isValid,
      timestamp: Date.now(),
      nonce: crypto.randomBytes(8).toString("hex")
    };

    const { data, iv } = encryptPayload(payload, SHARED_SECRET);
    const signatureHex = hmacSignHex(data, SHARED_SECRET);

    res.setHeader("x-signature", `sha256=${signatureHex}`);
    res.setHeader("x-cache-age-ms", String(Date.now() - cache.fetchedAt));
    res.setHeader("x-payload-valid-ms", String(PAYLOAD_VALID_MS));

    return res.status(200).json({ data, iv });
  } catch (err) {
    console.error("[VALIDATE ERROR]", err);
    return res.status(500).json({ error: "Internal Server Error" });
  }
}
