from __future__ import annotations

# HH-native engagement finding states (inspired by triage discipline, not copied from other tools).
FINDING_STATUSES = frozenset({"signal", "confirmed", "ready", "dismissed", "archived"})

ADVANCE_TARGETS = frozenset({"confirmed", "ready"})

ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "signal": frozenset({"confirmed", "dismissed", "archived"}),
    "confirmed": frozenset({"ready", "dismissed", "archived"}),
    "ready": frozenset({"archived"}),
    "dismissed": frozenset(),
    "archived": frozenset({"signal"}),
}

LEGACY_STATUS_MAP = {
    "candidate": "signal",
    "verified": "confirmed",
    "reportable": "ready",
    "rejected": "dismissed",
    "stale": "archived",
}


def validate_transition(current: str, new_status: str) -> None:
    if new_status not in FINDING_STATUSES:
        raise ValueError(f"invalid finding status: {new_status}")
    allowed = ALLOWED_TRANSITIONS.get(current, frozenset())
    if new_status not in allowed:
        raise ValueError(f"cannot move finding from {current} to {new_status}")


def evidence_required_for(status: str) -> bool:
    return status in {"confirmed", "ready"}


# The 7-Question Validation Gate for rigorous, zero-false-positive finding verification.
SEVEN_QUESTION_GATE = [
    ("Q1", "Self-Contained Reproduction", "Contains reproducible request/response or self-contained exploit steps"),
    ("Q2", "Security Boundary Violation", "Demonstrates actual boundary breach (not intended application behavior)"),
    ("Q3", "Live System Impact", "Backed by live server responses or state mutation rather than theoretical risk"),
    ("Q4", "Feasible Interaction Model", "Exploitable without impossible victim interaction or invalid assumptions"),
    ("Q5", "In-Scope Asset", "Target asset is explicitly verified and authorized"),
    ("Q6", "Root Cause Isolated", "Identifies specific parameter, endpoint, header, or architectural flaw"),
    ("Q7", "Actionable Remediation", "Provides concrete, unambiguous remediation guidance for developers"),
]


def evaluate_finding_gate(finding: dict, in_scope: bool = True) -> dict:
    """Evaluate a finding against the 7-Question Validation Gate."""
    title = str(finding.get("title") or "").strip()
    target = str(finding.get("target") or "").strip()
    evidence = str(finding.get("evidence") or "").strip()
    remediation = str(finding.get("remediation") or "").strip()
    status = str(finding.get("status") or "signal").strip().lower()

    results = []

    # Q1: Self-Contained Reproduction
    has_http = any(marker in evidence.upper() for marker in ("HTTP/", "GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "CURL", "REQUEST", "RESPONSE"))
    q1_pass = bool(evidence and (len(evidence) >= 20 or has_http))
    q1_detail = "Evidence contains raw HTTP / reproduction steps" if q1_pass else "Missing detailed reproduction payload/evidence"
    results.append({"id": "Q1", "name": SEVEN_QUESTION_GATE[0][1], "passed": q1_pass, "details": q1_detail})

    # Q2: Security Boundary Violation
    q2_pass = bool(title and len(title) >= 5 and status != "dismissed")
    q2_detail = f"Status '{status}' indicates active security claim" if q2_pass else "Finding is dismissed or missing descriptive title"
    results.append({"id": "Q2", "name": SEVEN_QUESTION_GATE[1][1], "passed": q2_pass, "details": q2_detail})

    # Q3: Live System Impact
    q3_pass = bool(evidence and len(evidence) >= 30 and not evidence.lower().startswith("theoretical"))
    q3_detail = "Live response / impact captured in evidence" if q3_pass else "Insufficient or purely theoretical evidence"
    results.append({"id": "Q3", "name": SEVEN_QUESTION_GATE[2][1], "passed": q3_pass, "details": q3_detail})

    # Q4: Feasible Interaction Model
    anti_patterns = ("requires root on client", "social engineering victim into clicking 10 times", "theoretical attacker")
    q4_pass = not any(pat in evidence.lower() for pat in anti_patterns)
    q4_detail = "Interaction model is feasible" if q4_pass else "Unrealistic prerequisites detected"
    results.append({"id": "Q4", "name": SEVEN_QUESTION_GATE[3][1], "passed": q4_pass, "details": q4_detail})

    # Q5: In-Scope Asset
    q5_pass = bool(target and in_scope)
    q5_detail = f"Target '{target}' validated" if q5_pass else "Missing target or out-of-scope asset"
    results.append({"id": "Q5", "name": SEVEN_QUESTION_GATE[4][1], "passed": q5_pass, "details": q5_detail})

    # Q6: Root Cause Isolated
    q6_pass = bool(title and (len(title.split()) >= 2 or "/" in title or "_" in title))
    q6_detail = f"Specific vector named: '{title}'" if q6_pass else "Title too vague to isolate root cause"
    results.append({"id": "Q6", "name": SEVEN_QUESTION_GATE[5][1], "passed": q6_pass, "details": q6_detail})

    # Q7: Actionable Remediation
    q7_pass = bool(remediation and len(remediation) >= 15)
    q7_detail = "Actionable developer remediation provided" if q7_pass else "Missing or incomplete remediation guidance"
    results.append({"id": "Q7", "name": SEVEN_QUESTION_GATE[6][1], "passed": q7_pass, "details": q7_detail})

    passed_count = sum(1 for r in results if r["passed"])
    # A finding is ready/verified if at least 6/7 criteria are met (including Q1, Q2, Q3, Q5)
    critical_pass = q1_pass and q2_pass and q3_pass and q5_pass
    overall_passed = critical_pass and (passed_count >= 6)

    return {
        "finding_id": finding.get("id", "unknown"),
        "title": title,
        "status": status,
        "passed": overall_passed,
        "score": f"{passed_count}/7",
        "passed_count": passed_count,
        "results": results,
    }


def format_gate_report(evaluation: dict) -> str:
    """Format a 7-Question Gate evaluation into a clean summary."""
    lines = [
        f"Validation Gate for {evaluation['finding_id']} · {evaluation['title']}",
        f"Verdict: {'✓ PASS (Submission-Ready)' if evaluation['passed'] else '× REVIEW REQUIRED'} [{evaluation['score']}]",
        "",
    ]
    for r in evaluation["results"]:
        mark = "✓" if r["passed"] else "×"
        lines.append(f"  {mark} {r['id']} ({r['name']}): {r['details']}")
    return "\n".join(lines)
