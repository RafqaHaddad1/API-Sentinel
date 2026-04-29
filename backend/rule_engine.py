import re
import time
from collections import defaultdict, deque
from typing import Any, Dict
from urllib.parse import unquote_plus

from backend.feature_extraction import SQL_PATTERNS, XSS_PATTERNS, CMD_PATTERNS, TRAVERSAL_PATTERNS

class RuleBasedDetectionEngine:
    def __init__(self, rate_window_seconds=60, rate_limit_per_ip=60):
        self.rate_window_seconds = rate_window_seconds
        self.rate_limit_per_ip = rate_limit_per_ip
        self.ip_request_times = defaultdict(deque)
        self.sql_patterns = SQL_PATTERNS
        self.xss_patterns = XSS_PATTERNS
        self.cmd_patterns = CMD_PATTERNS
        self.traversal_patterns = TRAVERSAL_PATTERNS

    def evaluate_request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        client_ip = req.get("client_ip", "unknown")
        headers = req.get("headers", {}) or {}
        body = str(req.get("body", "") or "")
        path = str(req.get("path", "") or "")
        method = str(req.get("method", "") or "")
        qp = req.get("query_params", {}) or {}
        text = self._build_text(method, path, qp, body)

        reasons, score = [], 0
        decision, label = "allow", "normal"
        for category, patterns in [
            ("SQLi", self.sql_patterns),
            ("XSS", self.xss_patterns),
            ("Path traversal", self.traversal_patterns),
            ("Command injection", self.cmd_patterns),
        ]:
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                    reasons.append(f"{category} pattern matched")
                    score += 90
                    decision, label = "block", "malicious"
                    break
            if decision == "block":
                break

        rate = self._check_rate(client_ip)
        if rate["matched"]:
            reasons.extend(rate["reasons"])
            score += rate["score"]
            if rate["decision"] == "block":
                decision, label = "block", "malicious"
            elif decision == "allow":
                decision, label = "flag", "suspicious"

        if any(path.lower().startswith(p) for p in ("/admin", "/transfer", "/internal")) and not (
            headers.get("authorization") or headers.get("Authorization")
        ):
            reasons.append("protected endpoint without authorization")
            score += 35
            if decision == "allow":
                decision, label = "flag", "suspicious"

        return {"decision": decision, "label": label, "risk_score": int(min(score, 100)), "reasons": reasons}

    def _build_text(self, method, path, qp, body):
        qp_text = " ".join(f"{k}={v}" for k, v in qp.items())
        raw = f"{method} {path} {qp_text} {body}"
        prev, cur = None, raw
        for _ in range(4):
            if cur == prev:
                break
            prev = cur
            try:
                cur = unquote_plus(cur)
            except Exception:
                break
        return cur.lower()

    def _check_rate(self, ip):
        now = time.time()
        q = self.ip_request_times[ip]
        q.append(now)
        while q and now - q[0] > self.rate_window_seconds:
            q.popleft()
        n = len(q)
        if n > self.rate_limit_per_ip * 3:
            return {"matched": True, "decision": "block", "score": 80, "reasons": [f"IP flooding: {n}/{self.rate_window_seconds}s"]}
        if n > self.rate_limit_per_ip:
            return {"matched": True, "decision": "flag", "score": 35, "reasons": [f"high request rate: {n}/{self.rate_window_seconds}s"]}
        return {"matched": False, "decision": "allow", "score": 0, "reasons": []}
