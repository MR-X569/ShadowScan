"""
app/scanner/plugins/active/__init__.py
--------------------------------------
Active scanner plugins.

Active plugins send crafted HTTP requests to the target to probe for
exploitable vulnerabilities. They should only be used against targets
the user has explicit authorisation to test.

Planned plugins (not yet implemented):
    - sql_injection             — Error-based and boolean-blind SQLi detection
    - xss_reflected             — Reflected cross-site scripting probes
    - xss_stored                — Stored XSS via form submission
    - ssrf_detection            — Server-side request forgery probes
    - path_traversal            — Directory traversal via URL manipulation
    - open_redirect             — Open redirect parameter fuzzing
    - command_injection         — OS command injection in parameters

To add a plugin, create a module in this directory and define a class
that inherits from ``BasePlugin`` and implements ``async run(context)``.
"""
