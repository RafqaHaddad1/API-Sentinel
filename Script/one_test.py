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