import fetch from "node-fetch";
import crypto from "crypto";

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const REPO_OWNER = process.env.REPO_OWNER || "fir17html"; //nama akun github lu
const REPO_NAME = process.env.REPO_NAME || "dbnew"; //nama repo
const FILE_PATH = process.env.FILE_PATH || "xmddb.json"; //lu isi nama file json di db lu

const ACCESS_KEY = process.env.ACCESS_KEY || "#xmdnihbos"; // wajib lu isi dan buat susah key nya hrs sama dengan yg bawah
const SHARED_SECRET = process.env.SHARED_SECRET || "#xmdnihbos"; // untuk encrypt + sign wajib lu isi dan key ini lu buat susah
const CACHE_TTL_MS = parseInt(process.env.CACHE_TTL_MS || "30000", 10);
const PAYLOAD_VALID_MS = parseInt(process.env.PAYLOAD_VALID_MS || "30000", 10); 
let cache = {
  data: null,
  fetchedAt: 0
};

const RATE_LIMIT_WINDOW_MS = 60_000; // 1 minute
const RATE_LIMIT_MAX = 30; // max requests per window per IP
const rateMap = new Map();

// Utilities
function timingSafeEqualStr(a = "", b = "") {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) {
    const max = Math.max(bufA.length, bufB.length);
    const a2 = Buffer.alloc(max);
    const b2 = Buffer.alloc(max);
    bufA.copy(a2);
    bufB.copy(b2);
    try {
      crypto.timingSafeEqual(a2, b2);
    } catch (e) {
    //biarin aja jgn ada e nya
    }
    return false;
  }
  try {
    return crypto.timingSafeEqual(bufA, bufB);
  } catch (e) {
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
  return crypto.createHmac("sha256", String(secret)).update(data).digest("hex");
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
  if (entry.count > RATE_LIMIT_MAX) return true;
  return false;
}

async function fetchTokensFromGitHub() {
  const url = `https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/contents/${FILE_PATH}`;

  const res = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `token ${GITHUB_TOKEN}`,
      "User-Agent": "token-validator",
      Accept: "application/vnd.github.v3+json"
    },
    redirect: "manual",
  });

  if (res.status >= 300 && res.status < 400) {
    throw new Error(`Unexpected redirect from GitHub: ${res.status}`);
  }
  if (!res.ok) {
    throw new Error(`GitHub API error ${res.status}`);
  }

  const json = await res.json();

  if (!json || typeof json.content !== "string") {
    throw new Error("GitHub response missing content");
  }

  const contentStr = Buffer.from(json.content, "base64").toString("utf8");

  let parsed;
  try {
    parsed = JSON.parse(contentStr);
  } catch (e) {
    throw new Error("tokens.json invalid JSON");
  }

  if (!parsed || !Array.isArray(parsed.tokens)) {
    throw new Error("tokens.json must contain an array 'tokens'");
  }

  cache.data = parsed;
  cache.fetchedAt = Date.now();

  return parsed;
}

// Handler
export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }


  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket.remoteAddress || "unknown";
  if (isRateLimited(ip)) {
    console.warn(`[RATE LIMIT] ${ip} exceeded rate limit`);
    return res.status(429).json({ error: "Too many requests" });
  }

  const apiKey = req.headers["x-api-key"] || req.headers["x-access-key"] || "";
  if (!timingSafeEqualStr(apiKey, ACCESS_KEY)) {
    console.warn(`[AUTH FAIL] IP=${ip} missing/invalid api key`);
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { token } = req.body || {};
  if (!token) return res.status(400).json({ valid: false, error: "Missing token in body" });

  try {
    if (cache.data && now - cache.fetchedAt < CACHE_TTL_MS) {
    } else {
      try {
        await fetchTokensFromGitHub();
      } catch (gitErr) {
        console.error("[GITHUB FETCH ERROR]", gitErr.message);
        if (!cache.data) {
          return res.status(500).json({ error: "Failed to fetch tokens and no cache available" });
        }

        console.warn("[FALLBACK] using cached token list due to fetch error");
      }
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
