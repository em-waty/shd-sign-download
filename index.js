// sign-download.js (DigitalOcean Functions - Node 18+)
// Presigns a GET for DigitalOcean Spaces using S3 Signature V2

import crypto from "crypto";

const BUCKET = process.env.SPACES_BUCKET || "700days";
const REGION = process.env.SPACES_REGION || "ams3";
const ACCESS_KEY = process.env.DO_ACCESS_KEY;
const SECRET_KEY = process.env.DO_SECRET_KEY;

const ENDPOINT_HOST = `${BUCKET}.${REGION}.digitaloceanspaces.com`;

// In production, replace "*" with your Webflow domain(s)
const CORS = {
  "Access-Control-Allow-Origin": "*", // e.g. "https://your-site.webflow.io"
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400",
  "Content-Type": "application/json"
};

function sigV2GetUrl({ key, ttlSec = 1800 }) {
  const method = "GET";
  const expires = Math.floor(Date.now() / 1000) + Math.max(60, Math.min(ttlSec, 24 * 3600));

  // This is the canonical resource used for signing — unencoded except for bucket/key format
  const canonicalResource = `/${BUCKET}/${key}`;

  const stringToSign = [
    method,
    "",          // Content-MD5
    "",          // Content-Type
    String(expires),
    canonicalResource
  ].join("\n");

  const signature = crypto
    .createHmac("sha1", SECRET_KEY)
    .update(stringToSign)
    .digest("base64");

  // Encode each path segment individually so reserved chars like #, ?, spaces don't break URL
  const encodedPath = key.split("/").map(encodeURIComponent).join("/");

  const url =
    `https://${ENDPOINT_HOST}/${encodedPath}` +
    `?AWSAccessKeyId=${encodeURIComponent(ACCESS_KEY)}` +
    `&Expires=${expires}` +
    `&Signature=${encodeURIComponent(signature)}`;

  return {
    url,
    expiresIn: (expires - Math.floor(Date.now() / 1000)),
    expiresAt: new Date(expires * 1000).toISOString()
  };
}

export async function main(params) {
  const method = (params.__ow_method || "").toUpperCase();

  if (!ACCESS_KEY || !SECRET_KEY || !BUCKET || !REGION) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: "Server misconfiguration" }) };
  }

  if (method === "OPTIONS") {
    return { statusCode: 204, headers: CORS, body: "" };
  }

  // Health check (masked)
  if (method === "GET") {
    return {
      statusCode: 200,
      headers: CORS,
      body: JSON.stringify({
        alive: true,
        bucket: BUCKET,
        region: REGION,
        accessKeySuffix: (ACCESS_KEY || "").slice(-4)
      })
    };
  }

  if (method !== "POST") {
    return { statusCode: 405, headers: CORS, body: JSON.stringify({ error: "Method Not Allowed" }) };
  }

  const key = params.key;
  const ttlSec = Number(params.ttlSec ?? 1800);

  if (typeof key !== "string" || !key.length) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: "Missing 'key'" }) };
  }

  // Ensure no leading slashes
  const cleanKey = key.replace(/^\/+/, "");

  // 🔒 Restrict to processed video directory
  if (!/^uploads-shd\//.test(cleanKey)) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: "Invalid key prefix" }) };
  }

  // 🔒 Block path traversal attempts
  if (cleanKey.includes("..")) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: "Invalid key" }) };
  }

  const { url, expiresIn, expiresAt } = sigV2GetUrl({ key: cleanKey, ttlSec });
  return { statusCode: 200, headers: CORS, body: JSON.stringify({ url, expiresIn, expiresAt, key: cleanKey }) };
}
