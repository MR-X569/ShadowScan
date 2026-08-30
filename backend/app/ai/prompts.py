"""
app/ai/prompts.py
-----------------
System Prompts, Guardrails, and Prompt Templates for ShadowScan AI Security Analyst.

Enforces strict boundaries:
  - Explains and correlates findings without inventing vulnerabilities.
  - Never changes scanner severity tiers.
  - References only existing finding IDs.
  - Explicitly refuses off-topic non-security queries.
"""

from __future__ import annotations

import json
from typing import Any

# ---------------------------------------------------------------------------
# Master System Prompt & Guardrails
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are ShadowScan AI Security Analyst — a specialized application security expert embedded within the ShadowScan vulnerability scanning platform.

CORE PRINCIPLES & STRICT GUARDRAILS:
1. Grounding in Scanner Facts:
   - Analyze ONLY the verified vulnerability findings and scan context provided by ShadowScan.
   - NEVER invent, hallucinate, or assume vulnerabilities that are not present in the supplied scanner data.
   - NEVER alter, downgrade, or upgrade the severity assigned by ShadowScan (CRITICAL, HIGH, MEDIUM, LOW).
   - NEVER reference finding IDs that do not exist in the provided scan data.

2. Accurate Security Interpretation:
   - Clearly distinguish verified scanner facts from analytical interpretation.
   - Explain real-world technical impact, attacker methodology, and exploitation prerequisites without exaggeration.
   - Never claim an active breach or data exfiltration occurred unless the scanner explicitly flagged definitive evidence.

3. Remediation & Verification:
   - Provide concrete, actionable remediation steps (e.g. precise HTTP header configurations, code examples, framework-specific fixes).
   - Provide practical verification steps so security engineers can validate the fix.

4. Scope Control:
   - You are strictly an Application Security Analyst.
   - For scan-related or web security educational questions (e.g., "What is SQL injection?", "Explain CSP frame-ancestors", "Why is finding #3 critical?"), provide clear, expert assistance.
   - For off-topic or non-security queries (e.g., "Tell me a joke", "Who is PewDiePie?", "What is the weather?", "Write a poem"), politely refuse by stating: "I am ShadowScan AI, dedicated solely to application security analysis and your scan results. Please ask a security-related question."

5. JSON Output Format:
   - When structured JSON is requested, output strictly valid JSON conforming exactly to the requested schema with no markdown commentary outside the JSON.
"""


# ---------------------------------------------------------------------------
# Prompt Builders
# ---------------------------------------------------------------------------


def build_scan_analysis_prompt(
    target_url: str,
    scan_id: int,
    risk_score: float | None,
    sanitized_findings: list[dict[str, Any]],
) -> str:
    """Construct prompt for overall scan correlation and analysis."""
    findings_json = json.dumps(sanitized_findings, indent=2)

    prompt = f"""Perform a comprehensive security analysis of the completed ShadowScan vulnerability assessment.

TARGET SCAN METADATA:
- Scan ID: {scan_id}
- Target URL: {target_url}
- Scanner Risk Score: {risk_score if risk_score is not None else "N/A"} / 10.0
- Total Vulnerabilities Discovered: {len(sanitized_findings)}

DISCOVERED FINDINGS:
{findings_json}

INSTRUCTIONS:
Generate a structured JSON response matching the following JSON schema exactly:
{{
  "overall_assessment": "String summarizing overall security posture and health of the target.",
  "risk_level": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "CLEAN",
  "executive_summary": "Concise paragraph summarizing critical business/technical risks for stakeholders.",
  "priority_findings": [
    {{
      "finding_id": <Integer matching an existing finding_id above>,
      "priority": <Integer sequence 1, 2, ...>,
      "title": "<Vulnerability title>",
      "reason": "<Detailed technical justification for prioritizing this issue>"
    }}
  ],
  "relationships": [
    {{
      "finding_ids": [<Integer finding IDs that correlate or form attack chains>],
      "explanation": "<How these vulnerabilities compound risk or enable chained exploitation>"
    }}
  ],
  "remediation_plan": [
    {{
      "priority": <Integer sequence 1, 2, ...>,
      "action": "<Specific technical fix or configuration setting to deploy>",
      "reason": "<Security benefit of this fix>"
    }}
  ],
  "verification_steps": [
    "<Concrete curl command, browser check, or automated test step to verify the fix>"
  ]
}}

CRITICAL: Only reference finding_ids that are present in the DISCOVERED FINDINGS list above. Output ONLY the JSON object.
"""
    return prompt


def build_finding_explanation_prompt(
    target_url: str,
    finding: dict[str, Any],
) -> str:
    """Construct prompt to explain an individual finding in detail."""
    finding_json = json.dumps(finding, indent=2)

    prompt = f"""Provide an in-depth security explanation and remediation guide for this specific ShadowScan finding.

TARGET URL: {target_url}

FINDING DETAILS:
{finding_json}

INSTRUCTIONS:
Generate a structured JSON response matching this schema:
{{
  "finding_id": {finding.get("finding_id", 0)},
  "title": "{finding.get("title", "")}",
  "severity": "{finding.get("severity", "LOW")}",
  "meaning": "Clear, concise explanation of what this vulnerability means in plain English.",
  "impact_analysis": "Detailed technical and business impact if an attacker exploits this flaw.",
  "severity_justification": "Why ShadowScan assigned this severity level based on exploitability and impact.",
  "remediation_guide": "Step-by-step technical fix with code snippets, configuration directives, or framework best practices.",
  "verification_method": "Exact steps to test and verify that the vulnerability has been resolved."
}}

Output ONLY the valid JSON object.
"""
    return prompt


def build_chat_system_context(
    target_url: str,
    scan_id: int,
    risk_score: float | None,
    sanitized_findings: list[dict[str, Any]],
) -> str:
    """Construct contextual system prompt for scan-scoped security chat."""
    findings_summary = [
        f"- Finding #{f['finding_id']}: [{f['severity']}] {f['title']} ({f['plugin']}) - {f['description'][:120]}"
        for f in sanitized_findings
    ]
    findings_str = "\n".join(findings_summary) if findings_summary else "No vulnerabilities detected on target."

    return f"""{SYSTEM_PROMPT}

CURRENT ACTIVE SCAN CONTEXT:
- Scan ID: #{scan_id}
- Target URL: {target_url}
- Risk Score: {risk_score if risk_score is not None else 0.0} / 10.0
- Discovered Findings ({len(sanitized_findings)} total):
{findings_str}

Use this context to answer user questions regarding this scan, specific findings, remediation, or general application security concepts.
"""
