"""
API Sentinel — Utility: Download SQLite Database (Section 29 from original notebook).
"""

# ======================================================================
# ## 29. Utility — Download SQLite Database
#
# Colab-only helper: downloads `sam_ads.db` to your local machine so you can inspect logs, alerts, predictions, etc.
# ======================================================================

from google.colab import files
files.download("sam_ads.db")
