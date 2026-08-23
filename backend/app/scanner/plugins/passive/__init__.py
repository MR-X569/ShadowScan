"""
app/scanner/plugins/passive/__init__.py
---------------------------------------
Passive scanner plugins.

Passive plugins inspect existing response data without sending additional
HTTP requests to the target. They are safe to run against any target.

Planned plugins (not yet implemented):
    - missing_security_headers  — X-Frame-Options, CSP, HSTS, X-XSS-Protection
    - ssl_certificate_check     — Expiry, weak cipher suites, misconfigurations
    - cookie_security_flags     — Missing HttpOnly / Secure / SameSite flags
    - information_disclosure    — Server version banners, stack traces, debug info
    - robots_txt_analysis       — Sensitive paths exposed in robots.txt
    - cors_misconfiguration     — Overly permissive CORS headers

To add a plugin, create a module in this directory and define a class
that inherits from ``BasePlugin`` and implements ``async run(context)``.
"""
