"""
app/scanner/plugins/ai/__init__.py
-----------------------------------
AI-powered scanner plugins.

AI plugins use large language models or machine learning classifiers to
perform semantic analysis, pattern recognition, and advanced vulnerability
detection that rule-based plugins cannot reliably achieve.

Planned plugins (not yet implemented):
    - ai_content_analysis       — Detect sensitive data exposure via LLM
    - ai_auth_flow_review       — Semantic review of authentication patterns
    - ai_api_schema_audit       — Audit inferred API schema for insecure design
    - ai_risk_scorer            — Aggregate findings into an overall risk score

To add a plugin, create a module in this directory and define a class
that inherits from ``BasePlugin`` and implements ``async run(context)``.
"""
