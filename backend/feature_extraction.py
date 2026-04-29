import re
import math
from urllib.parse import urlparse, parse_qs, unquote_plus

SQL_PATTERNS = [
    r"\bunion\b\s+(all\s+)?\bselect\b",
    r"\bor\b\s+\d+\s*=\s*\d+",
    r"\band\b\s+\d+\s*=\s*\d+",
    r"'\s*or\s*'?\d+'?\s*=\s*'?\d+",
    r"\bdrop\b\s+\btable\b",
    r"\binsert\b\s+\binto\b",
    r"\bdelete\b\s+\bfrom\b",
    r"\bupdate\b[^,;]{0,80}\bset\b",
    r"\binformation_schema\b",
    r"\bsleep\s*\(\s*\d+\s*\)",
    r"\bbenchmark\s*\(",
    r"\bxp_cmdshell\b",
    r";\s*--",
    r"--\s*$",
    r"/\*.*?\*/",
]

XSS_PATTERNS = [
    r"<script[^>]*>", r"</script>", r"javascript\s*:",
    r"\bon(error|load|click|mouseover|focus|submit)\s*=",
    r"<img[^>]+on\w+\s*=", r"<svg[^>]+on\w+\s*=", r"<iframe[^>]*>",
    r"document\s*\.\s*cookie", r"\beval\s*\(", r"\bfromcharcode\s*\(",
]

CMD_PATTERNS = [
    r";\s*(rm|cat|ls|wget|curl|nc|bash|sh|powershell)\b",
    r"\|\s*(rm|cat|ls|wget|curl|nc|bash|sh|powershell)\b",
    r"&&\s*(rm|cat|ls|wget|curl|nc|bash|sh|powershell)\b",
    r"\$\(.+?\)", r"`[^`]+`", r"\brm\s+-rf\s+/",
]

TRAVERSAL_PATTERNS = [
    r"\.\./", r"\.\.\\", r"%2e%2e%2f", r"/etc/passwd", r"/etc/shadow",
    r"\bwindows\\system32\b", r"\bboot\.ini\b",
]

BAD_UA_PATTERNS = [
    r"sqlmap", r"nikto", r"nmap", r"acunetix", r"\bburp\b",
    r"owasp\s*zap", r"\bzap\b", r"masscan", r"gobuster",
]

def deep_decode(x, max_passes=4):
    if x is None:
        return ""
    x = str(x)
    for _ in range(max_passes):
        try:
            decoded = unquote_plus(x)
        except Exception:
            break
        if decoded == x:
            break
        x = decoded
    return x

def clean_text(x):
    return deep_decode(x).lower().strip()

def shannon_entropy(s):
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def count_pattern_hits(text, patterns):
    return sum(1 for p in patterns if re.search(p, text, re.IGNORECASE | re.DOTALL))

def build_request_features(path, payload="", query_params=None, headers=None, method="GET", user_agent=""):
    headers = headers or {}
    lower_headers = {str(k).lower(): str(v) for k, v in headers.items()}

    method_text = clean_text(method)
    user_agent_text = clean_text(user_agent or lower_headers.get("user-agent", ""))
    payload_text = clean_text(payload)
    path_text = clean_text(path)

    parsed = urlparse(path_text)
    raw_path = parsed.path if parsed.path else path_text
    merged_query = {k: v for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

    if isinstance(query_params, dict):
        for k, v in query_params.items():
            merged_query[clean_text(str(k))] = (
                [clean_text(str(i)) for i in v] if isinstance(v, (list, tuple)) else clean_text(str(v))
            )

    query_string = "&".join(
        f"{k}={','.join(v) if isinstance(v, list) else v}" for k, v in merged_query.items()
    )
    full_text = f"{method_text} {raw_path} {query_string} {payload_text}".lower().strip()
    n = max(len(full_text), 1)
    special_count = len(re.findall(r"[<>'\";(){}\[\]$`|]", full_text))
    digit_count = sum(c.isdigit() for c in full_text)

    return {
        "url_length": len(raw_path),
        "query_length": len(query_string),
        "payload_length": len(payload_text),
        "full_request_length": len(full_text),
        "user_agent_length": len(user_agent_text),
        "path_depth": raw_path.strip("/").count("/") + (1 if raw_path.strip("/") else 0),
        "param_count": len(merged_query),
        "header_count": len(headers),
        "equals_count": full_text.count("="),
        "ampersand_count": full_text.count("&"),
        "slash_count": full_text.count("/"),
        "dot_count": full_text.count("."),
        "percent_count": full_text.count("%"),
        "digit_count": digit_count,
        "uppercase_count": sum(c.isupper() for c in full_text),
        "special_char_count": special_count,
        "digit_ratio": digit_count / n,
        "special_char_ratio": special_count / n,
        "percent_ratio": full_text.count("%") / n,
        "payload_entropy": shannon_entropy(payload_text),
        "query_entropy": shannon_entropy(query_string),
        "sql_pattern_hits": count_pattern_hits(full_text, SQL_PATTERNS),
        "xss_pattern_hits": count_pattern_hits(full_text, XSS_PATTERNS),
        "cmd_pattern_hits": count_pattern_hits(full_text, CMD_PATTERNS),
        "traversal_pattern_hits": count_pattern_hits(full_text, TRAVERSAL_PATTERNS),
        "bad_ua_pattern_hits": count_pattern_hits(user_agent_text, BAD_UA_PATTERNS),
        "has_cookie": int("cookie" in lower_headers),
        "has_authorization": int("authorization" in lower_headers),
        "method_GET": int(method_text == "get"),
        "method_POST": int(method_text == "post"),
        "method_PUT": int(method_text == "put"),
        "method_DELETE": int(method_text == "delete"),
        "method_PATCH": int(method_text == "patch"),
    }
