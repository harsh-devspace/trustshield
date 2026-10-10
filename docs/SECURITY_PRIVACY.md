# TrustShield — Security & Privacy Notes

## Privacy Principles

TrustShield is built on the principle that protecting users from phishing should not require surveilling their browsing activity.

### Data Minimization in Practice

The feature extraction pipeline is designed so that sensitive data cannot be accidentally transmitted:

```
Content Script (content.js)        → Only reads:
  document.querySelectorAll('form') → form COUNT (not content)
  form.getAttribute('action')       → target hostname (not values)
  input[type="password"]            → COUNT only (not value)
  iframe.getAttribute('src')        → target hostname (not src HTML)
  document.title.length             → LENGTH only (not title text)

Background Service Worker           → Only sends:
  17 numeric URL structure features  (no URL stored on server)
  8 numeric DOM counts               (no HTML content)
```

### What Is Never Transmitted

| Data Type | Status |
|-----------|--------|
| Browsing history | ❌ Never accessed |
| Form field values | ❌ Never accessed |
| Passwords | ❌ Never accessed |
| Cookies | ❌ Never accessed |
| Authentication tokens | ❌ Never accessed |
| Page HTML content | ❌ Never transmitted |
| User account information | ❌ Never accessed |
| Full URL after analysis | ❌ Not stored by backend |

### What IS Transmitted Per Scan

```json
{
  "url": "https://example.com",           // The URL being analyzed
  "url_features": {
    "url_length": 23,                     // integer
    "hostname_length": 11,                // integer  
    "subdomain_count": 1,                 // integer
    "is_https": 1,                        // 0 or 1
    "has_ip_host": 0,                     // 0 or 1
    "has_at_symbol": 0,                   // 0 or 1
    "has_double_slash": 0,                // 0 or 1
    "dash_in_hostname": 0,                // 0 or 1
    "dot_count": 2,                       // integer
    "has_suspicious_keywords": 0,         // 0 or 1
    "path_length": 1,                     // integer
    "query_length": 0,                    // integer
    "has_port": 0,                        // 0 or 1
    "has_suspicious_tld": 0,              // 0 or 1
    "special_char_count": 0,              // integer
    "slash_count": 1,                     // integer
    "has_encoding": 0                     // 0 or 1
  },
  "dom_features": {
    "has_password_input": 0,              // 0 or 1
    "password_input_count": 0,            // integer
    "form_count": 0,                      // integer
    "external_form_count": 0,             // integer
    "external_iframe_count": 0,           // integer
    "has_external_form": 0,               // 0 or 1
    "title_length": 7,                    // integer (length only)
    "has_favicon": 1                      // 0 or 1
  }
}
```

---

## Security Protections

### SSRF Protection

The backend explicitly validates submitted URLs and blocks:

- `127.0.0.0/8` — Loopback
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` — RFC 1918 private
- `169.254.0.0/16` — Link-local (includes AWS metadata at 169.254.169.254)
- `::1/128`, `fc00::/7`, `fe80::/10` — IPv6 private/loopback
- `224.0.0.0/4`, `ff00::/8` — Multicast
- Hostnames: `localhost`, `metadata.google.internal`

**Note:** The backend never fetches the submitted URL. SSRF protection is defense-in-depth against potential future URL fetching functionality.

### Input Validation

- All inputs validated by Pydantic v2 with strict field types
- URL field: must start with `http://` or `https://`, max 2048 chars
- Numeric features: typed as `Optional[int]`, defaults to 0 if missing
- Generic exception handler prevents internal stack traces from leaking

### Extension Permissions

| Permission | Why Required | Least Privilege |
|-----------|--------------|-----------------|
| `activeTab` | Read current tab URL | Scoped to active tab only |
| `storage` | Cache scan results | Local browser storage only |
| `scripting` | DOM feature extraction | Executes read-only JS in tab |
| `webNavigation` | Clear badge on navigation | Monitors events only |
| `declarativeNetRequest` | Future: block known threats | Declarative, no arbitrary network access |
| `host_permissions: <all_urls>` | Required for scripting API | Needed to analyze any URL |

### Content Security Policy

```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self'"
}
```

No inline scripts, no eval, no external script sources in extension pages.

### ML Model Security

- Model artifact loaded from local filesystem only (no remote loading)
- Model output is a probability (0.0–1.0), not a binary decision alone
- Predictions are blended with heuristics — no single-point-of-failure
- Model degrades gracefully: if missing, falls back to heuristics-only

---

## Known Limitations

1. **No real-time threat intelligence:** The backend does not query SafeBrowsing, PhishTank, or VirusTotal. These integrations are planned but require API keys.

2. **Extension can be disabled:** Users can disable the extension or bypass the warning page.

3. **Domain spoofing (IDN homograph):** Internationalized domain names using lookalike characters are not explicitly checked.

4. **Cached results:** Scan results are cached for 5 minutes. A URL converted from safe to malicious during that window will not be re-scanned until the cache expires.

5. **No certificate validation:** The backend checks for HTTPS but does not validate TLS certificate authenticity.
