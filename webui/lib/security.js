function buildSecurityHeaders(contentType) {
  const headers = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  };

  if (contentType) headers["Content-Type"] = contentType;
  return headers;
}

function isSameOriginApiPath(requestUrl) {
  return typeof requestUrl === "string" && /^\/api\//.test(requestUrl);
}

function shouldAttachAuthorization(requestUrl, origin) {
  if (typeof requestUrl !== "string" || typeof origin !== "string") return false;
  try {
    const target = new URL(requestUrl, origin);
    const base = new URL(origin);
    return target.origin === base.origin && isSameOriginApiPath(target.pathname);
  } catch (e) {
    return false;
  }
}

module.exports = { buildSecurityHeaders, isSameOriginApiPath, shouldAttachAuthorization };
