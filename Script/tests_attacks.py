"""
API Sentinel — Testing: Attack Simulations (Section 28 from original notebook).
"""
import requests
# ======================================================================
# ## 28. Testing — Attack Simulations
#
# These should be **blocked** by the proxy. Each cell fires one attack category and prints the response.
# ======================================================================

# --- Attack: Cross-Site Scripting (XSS) in POST body ---
r = requests.post(
    "http://127.0.0.1:8000/comment",
    data="<script>alert('xss')</script>"
)
print(r.status_code, r.text)

# --- Attack: SQL Injection via query parameter ---
# (imports consolidated into section 1)
r = requests.get("http://127.0.0.1:8000/files?id=1 UNION SELECT password")
print(r.status_code, r.text)

# --- Attack: Path Traversal via query parameter ---
r = requests.get("http://127.0.0.1:8000/files?name=../etc/passwd")
print(r.status_code, r.text)

# --- Attack: URL-encoded SQL Injection ---
r = requests.get(
    "http://127.0.0.1:8000/api/products",
    params={"q": "%27%20OR%201%3D1%20--"}
)
print(r.status_code)
print(r.text)

# 1. Suspicious SQL keyword (light)
r = requests.get(
    "http://127.0.0.1:8000/api/products",
    params={"search": "select phone"}
)
print(r.status_code)
print(r.text)

# 2. Strange encoding / probing
r = requests.get(
    "http://127.0.0.1:8000/hello?input=%27%20OR%201=1"
)
print(r.status_code)
print(r.text)

# 3. Suspicious user agent
r = requests.get(
    "http://127.0.0.1:8000/hello",
    headers={"User-Agent": "sqlmap/1.0"}
)
print(r.status_code)
print(r.text)

# 4. Large payload (probing)
r = requests.post(
    "http://127.0.0.1:8000/comment",
    json={"text": "A" * 5000}
)
print(r.status_code)
print(r.text)

# 5. Path traversal attempt (mild)
r = requests.get(
    "http://127.0.0.1:8000/files?name=../../etc/passwd"
)
print(r.status_code)
print(r.text)

import requests

# Should be NORMAL
r = requests.get("http://127.0.0.1:8000/files")
print("Test 1 (benign):", r.status_code)

# Should be MALICIOUS (full SQL injection)
r = requests.get("http://127.0.0.1:8000/files?id=1 UNION SELECT password")
print("Test 2 (SQLi):", r.status_code)

# Should be SUSPICIOUS (weak signal — single keyword, no full pattern)
r = requests.get("http://127.0.0.1:8000/api/products?search=select+something")
print("Test 3 (weak SQL):", r.status_code)

# Should be SUSPICIOUS (encoded chars, no full pattern)
r = requests.get("http://127.0.0.1:8000/files?q=%27%20test")
print("Test 4 (encoded):", r.status_code)

# 1. SQL Injection (classic)
r = requests.get(
    "http://127.0.0.1:8000/api/products",
    params={"id": "1 OR 1=1"}
)
print(r.status_code)
print(r.text)

# 2. SQL UNION attack
r = requests.get(
    "http://127.0.0.1:8000/api/products",
    params={"search": "test UNION SELECT username, password FROM users"}
)
print(r.status_code)
print(r.text)

# 3. XSS attack
r = requests.post(
    "http://127.0.0.1:8000/comment",
    json={"text": "<script>alert('xss')</script>"}
)
print(r.status_code)
print(r.text)

# 4. Command injection
r = requests.get(
    "http://127.0.0.1:8000/api/run",
    params={"cmd": "ls; rm -rf /"}
)
print(r.status_code)
print(r.text)

# 5. Time-based SQL injection
r = requests.get(
    "http://127.0.0.1:8000/api/products",
    params={"id": "1; SLEEP(5)"}
)
print(r.status_code)
print(r.text)

# 6. Encoded XSS
r = requests.get(
    "http://127.0.0.1:8000/comment?text=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
)
print(r.status_code)
print(r.text)

# 7. Dangerous headers (token abuse simulation)
r = requests.get(
    "http://127.0.0.1:8000/hello",
    headers={
        "Authorization": "Bearer fake_token",
        "X-Forwarded-For": "1.2.3.4, 5.6.7.8"
    }
)
print(r.status_code)
print(r.text)

