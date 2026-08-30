"""
app/scanner/plugins/passive/__init__.py
---------------------------------------
Passive scanner plugins.

Passive plugins inspect existing response data and execute safe, non-destructive
probes against the target. They are safe to run against any target.

Implemented plugins:
    - security_headers         — CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer, Permissions
    - clickjacking             — Anti-framing protection analysis (X-Frame-Options, CSP frame-ancestors)
    - cookie_security          — Missing HttpOnly / Secure / SameSite flags, prefix rules, sensitive cookies
    - technology_detection     — Web server, framework, CMS, and runtime fingerprinting
    - cors_misconfiguration    — Origin reflection, null origin trust, wildcard ACAO, credentials leakage
    - ssl_tls                  — Certificate expiry, chain validity, self-signed certs
    - tls_ciphers              — TLS protocol versions (1.0, 1.1, 1.2, 1.3), cipher key length, RC4/3DES/PFS
    - info_disclosure          — Server version banners, tech headers, stack traces, sensitive files (.env, .git)
    - robots_txt               — Sensitive paths exposed in robots.txt
    - security_policy          — RFC 9116 security.txt policy validation and security metadata disclosure
    - sitemap                  — URLs and sensitive paths in sitemap.xml
    - crawler                  — Same-origin attack surface mapping, form/parameter extraction, JS API route discovery
    - api_security             — Exposed OpenAPI/Swagger specs, public GraphQL introspection and IDE consoles
    - open_redirect            — Unvalidated external redirection in URL query parameters
    - directory_listing        — Exposed directory indexes and backup/database archive files
    - host_header              — Host Header Injection in redirects, canonical links, and password recovery
    - http_methods             — Exposed HTTP methods (OPTIONS Allow, TRACE/XST, PUT, DELETE, CONNECT)
    - csrf_check               — Missing Anti-CSRF tokens and unsafe state-changing GET endpoints
    - xss                      — Reflected Cross-Site Scripting (XSS) input reflection and escaping checks
    - xxe                      — XML External Entity (XXE) and inline entity resolution checks
    - path_traversal           — Local file path traversal and arbitrary file read (/etc/passwd, win.ini)
    - jwt_security             — Insecure JWT configuration (alg:none, exposed credentials, missing exp)
    - ssrf                     — Server-Side Request Forgery (SSRF) and external URL fetching parameters
    - ssti                     — Server-Side Template Injection (SSTI) arithmetic evaluation checks
    - command_injection        — OS command injection reflection and shell interpreter error analysis
    - sqli                     — Error-based and boolean-based SQL injection vulnerability analysis
    - ldap_injection           — LDAP search filter injection and directory service parser error diagnostics
    - nosql_injection          — NoSQL operator injection and boolean differential vulnerability analysis
    - prototype_pollution      — Server-side and client-side JavaScript prototype pollution analysis
    - subdomain_takeover       — Dangling DNS CNAMEs and orphaned cloud service detection
    - crlf_injection           — HTTP Response Splitting and CRLF header injection analysis
    - websocket_security       — Cross-Site WebSocket Hijacking (CSWSH) and transport encryption checks
    - hsts_preloading          — Strict-Transport-Security policy validation and browser preload eligibility
    - x_content_type_options   — MIME-sniffing protection and content-type confusion analysis
    - cache_control_security   — Sensitive response anti-caching and Web Cache Deception analysis
    - clickjacking_advanced    — Advanced CSP frame-ancestors, XFO precedence, and policy conflict analysis
    - cors_credentials         — Credentialed CORS, origin reflection, and null-origin trust analysis
    - redirect_chain           — Multi-hop HTTP redirect tracing, transport downgrades, and token leak analysis
    - source_map_disclosure    — JavaScript and CSS source-map exposure and original source code disclosure
    - graphql_introspection    — Dedicated GraphQL introspection, schema leakage, and IDE console analysis
    - form_action_hijacking    — Form action target transport downgrades, external cross-origin leaks, and CSP checks
    - mixed_content            — HTTPS Mixed Content active and passive subresource analysis
    - cross_origin_isolation   — COOP, COEP, and CORP cross-origin isolation and Spectre defense analysis
    - sri_integrity            — Subresource Integrity (SRI) validation on external scripts and stylesheets
    - sensitive_data           — Exposed API keys, tokens, private keys, and database connection strings

To add a plugin, create a module in this directory and define a class
that inherits from ``BasePlugin`` and implements ``async run(context)``.
"""
