"""
API Sentinel — Testing: Benign Requests (Section 27 from original notebook).
"""
import requests
# ======================================================================
# ## 27. Testing — Benign Requests
#
# Sanity checks: legitimate requests should be allowed through and return 200.
# ======================================================================

# --- Benign test: simple GET ---
# (imports consolidated into section 1)
r = requests.get("http://127.0.0.1:8000/files")
print("Status:", r.status_code)
print("Response:", r.text)

# --- Benign test: simple GET ---
# (imports consolidated into section 1)
r = requests.get("http://127.0.0.1:8000/hello")
print("Status:", r.status_code)
print("Response:", r.text)

# --- Benign test: GET with clean query params ---

r = requests.get(
    "http://127.0.0.1:8000/api/products",
    params={"page": 1, "limit": 10}
)

print(r.status_code)
print(r.text)

# --- Benign test: GET with extra harmless params ---

r = requests.get(
    "http://127.0.0.1:8000/api/products",
    params={"page": "1", "limit": "10", "debug": "true", "random": "abc123"}
)
print(r.status_code)
print(r.text)

