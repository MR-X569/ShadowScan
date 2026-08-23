"""
app/scanner/plugins/__init__.py
-------------------------------
Root package for all ShadowScan scanner plugins.

Sub-packages:
    passive/  — Read-only checks that inspect response data without
                sending additional requests (headers, SSL, cookies, etc.)
    active/   — Interactive checks that send crafted payloads to the target
                (SQLi, XSS, SSRF, path traversal, etc.)
    ai/       — AI-powered semantic analysis and pattern recognition.

Plugin authors: place your plugin module in the appropriate sub-package.
No other files need to be changed for a plugin to be discovered.
"""
