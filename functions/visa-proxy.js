/**
 * Cloudflare Pages Function — Visa FX proxy.
 *
 * The browser pre-signs the X-Pay-Token (HMAC-SHA256 in Web Crypto) so the
 * shared secret never leaves the client. This function just relays the POST
 * to Visa and copies the response back with permissive CORS headers, since
 * Visa's own API does not serve them.
 */

const ALLOWED_HOSTS = new Set([
  "api.visa.com",
  "sandbox.api.visa.com",
]);

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function json(status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: CORS });
}

export async function onRequestPost({ request }) {
  let payload;
  try {
    payload = await request.json();
  } catch {
    return json(400, { error: "Body must be JSON" });
  }

  const { url, headers, body } = payload || {};
  if (typeof url !== "string" || !headers || typeof body !== "string") {
    return json(400, { error: "Expected { url, headers, body }" });
  }

  let target;
  try {
    target = new URL(url);
  } catch {
    return json(400, { error: "Invalid url" });
  }
  if (!ALLOWED_HOSTS.has(target.hostname)) {
    return json(400, { error: `Host not allowed: ${target.hostname}` });
  }

  const visaRes = await fetch(target.toString(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json",
      "x-pay-token": headers["x-pay-token"] || headers["X-Pay-Token"] || "",
    },
    body,
  });

  const text = await visaRes.text();
  return new Response(text, {
    status: visaRes.status,
    headers: {
      "Content-Type": visaRes.headers.get("Content-Type") || "application/json",
      ...CORS,
    },
  });
}
