"""
API Sentinel — Diagnostic Cells (extra notebook cells, originally unnumbered).

These are ad-hoc debugging / diagnostic snippets that were at the bottom of the
original notebook. Each block is preserved verbatim; run them individually as
needed when troubleshooting.
"""

# ----------------------------------------------------------------------
# Diagnostic block 1 (original notebook cell 85)
# ----------------------------------------------------------------------

# ===== DIAGNOSTIC =====
# Tells us EXACTLY what is in memory right now.

print("1. Is cell 18's build_request_features in memory?")
print("   ", callable(build_request_features))

print("\n2. What feature names does it produce for a benign GET /files?")
test = build_request_features(
    path="/files",
    headers={"user-agent": "python-requests/2.32.4"},
    method="GET",
)
print("   Feature keys:", sorted(test.keys()))

print("\n3. Does it have OLD features (BAD)?")
old = [k for k in test.keys() if k.startswith("has_sql") or k.endswith("_keyword_count")]
print("   Old features found:", old if old else "NONE — good!")

print("\n4. Does it have NEW features (GOOD)?")
new = [k for k in test.keys() if k.endswith("_pattern_hits")]
print("   New features found:", new)

print("\n5. SQL_PATTERNS list in memory — does it contain bare '--'?")
bare_dashes = [p for p in SQL_PATTERNS if p == r"--" or p == "--"]
print("   Bad bare '--' pattern:", bare_dashes if bare_dashes else "NONE — good!")
print("   Total SQL patterns:", len(SQL_PATTERNS))

print("\n6. What does feature_columns look like? (this is what was saved)")
print("   First 5:", feature_columns[:5])
print("   Has 'has_sql_keyword'?", "has_sql_keyword" in feature_columns)
print("   Has 'sql_pattern_hits'?", "sql_pattern_hits" in feature_columns)

print("\n7. What rf_model is loaded?")
import joblib, os
if os.path.exists("rf_model.pkl"):
    rf = joblib.load("rf_model.pkl")
    print("   rf_model loaded.")
    # If model has feature_names_in_
    if hasattr(rf, 'feature_names_in_'):
        print("   Model expects features:", list(rf.feature_names_in_)[:5], "...")
    else:
        # Try base estimator (CalibratedClassifierCV wraps it)
        try:
            base = rf.calibrated_classifiers_[0].estimator
            if hasattr(base, 'feature_names_in_'):
                print("   Model expects features:", list(base.feature_names_in_)[:10])
                old_in_model = [f for f in base.feature_names_in_ if f.startswith("has_sql") or f.endswith("_keyword_count")]
                print("   Model trained on OLD features?", old_in_model if old_in_model else "NO — good!")
        except Exception as e:
            print("   Could not inspect base model:", e)

print("\n8. Test a benign request through the full pipeline")
X_live, feats = extract_features("", {}, {"user-agent": "python-requests/2.32.4"}, "GET", "/files")
import joblib
rf = joblib.load("rf_model.pkl")
prob = rf.predict_proba(X_live)[0]
print("   RF prediction probabilities:", prob)
print("   Probability of malicious:", prob[1] if len(prob) > 1 else prob[0])
print("   --> If this is > 0.5, the model is trained wrong.")
print("   --> If this is < 0.3, the model works; the bug is elsewhere.")


# ----------------------------------------------------------------------
# Diagnostic block 2 (original notebook cell 86)
# ----------------------------------------------------------------------

# Force a fresh, isolated test of the live pipeline
import joblib, pandas as pd

# Load EVERYTHING fresh from disk
rf_fresh = joblib.load("rf_model.pkl")
fc_fresh = joblib.load("feature_columns.pkl")
print("Model expects", len(fc_fresh), "features:", fc_fresh)
print()

# Build features for a benign request
benign_feats = build_request_features(
    path="/files",
    headers={"user-agent": "python-requests/2.32.4"},
    method="GET",
)
print("Benign feature values:")
for k in fc_fresh:
    print(f"   {k}: {benign_feats.get(k, '???')}")
print()

# Predict
benign_X = pd.DataFrame([{c: benign_feats.get(c, 0) for c in fc_fresh}])[fc_fresh]
print("Benign DataFrame shape:", benign_X.shape)
print("Benign prediction:", rf_fresh.predict_proba(benign_X)[0])
print()

# Now an attack
attack_feats = build_request_features(
    path="/files",
    query_params={"id": "1 UNION SELECT password"},
    headers={"user-agent": "sqlmap/1.0"},
    method="GET",
)
attack_X = pd.DataFrame([{c: attack_feats.get(c, 0) for c in fc_fresh}])[fc_fresh]
print("Attack prediction:", rf_fresh.predict_proba(attack_X)[0])


# ----------------------------------------------------------------------
# Diagnostic block 3 (original notebook cell 87)
# ----------------------------------------------------------------------

# Find out what your CSIC label column actually contains
import pandas as pd
df_check = pd.read_csv("csic_database.csv")
print("Columns:", list(df_check.columns))
print()

# Check every plausible label column
for col in ["classification", "label", "Class", "attack_type", "Type"]:
    if col in df_check.columns:
        print(f"=== Column '{col}' unique values + counts ===")
        print(df_check[col].value_counts())
        print()


# ----------------------------------------------------------------------
# Diagnostic block 4 (original notebook cell 88)
# ----------------------------------------------------------------------

# Verify the labels that ACTUALLY went into training
import pandas as pd

# Reload csic raw
df_raw = pd.read_csv("csic_database.csv")
print("Raw CSV classification counts:")
print(df_raw["classification"].value_counts())
print()

# Now check what build_binary_label produced
test_y = build_binary_label(df_raw.copy())
print("After build_binary_label:")
print(test_y.value_counts())
print()

# And verify the rows are aligned to attacks
print("Sample of normal rows (label=0):")
df_check = df_raw.copy()
df_check["bin_label"] = test_y
print(df_check[df_check["bin_label"] == 0][["Method", "URL", "classification"]].head(3))
print()
print("Sample of attack rows (label=1):")
print(df_check[df_check["bin_label"] == 1][["Method", "URL", "classification"]].head(3))


# ----------------------------------------------------------------------
# Diagnostic block 5 (original notebook cell 89)
# ----------------------------------------------------------------------

# ===== TRAINING PIPELINE DIAGNOSTIC =====
import pandas as pd
import numpy as np

# 1. Re-run feature extraction the same way cell 18 does
df_raw = pd.read_csv("csic_database.csv")
df_raw = df_raw.rename(columns={"URL": "url", "content": "payload",
                                 "Method": "method", "User-Agent": "user_agent",
                                 "lenght": "length"})
for col in ["url", "payload", "method", "user_agent"]:
    if col not in df_raw.columns:
        df_raw[col] = ""
    df_raw[col] = df_raw[col].apply(clean_text)

df_raw["label"] = build_binary_label(df_raw)

print("1. How many rows have empty payload?")
print(f"   normal rows with empty payload: {((df_raw['label']==0) & (df_raw['payload']=='')).sum()} / {(df_raw['label']==0).sum()}")
print(f"   attack rows with empty payload: {((df_raw['label']==1) & (df_raw['payload']=='')).sum()} / {(df_raw['label']==1).sum()}")
print()

print("2. Sample 3 normal URLs and 3 attack URLs:")
print("   NORMAL examples:")
for url in df_raw[df_raw["label"]==0]["url"].head(3):
    print(f"     {url[:120]}")
print("   ATTACK examples:")
for url in df_raw[df_raw["label"]==1]["url"].head(3):
    print(f"     {url[:120]}")
print()

print("3. Build features for one normal and one attack row:")
normal_row = df_raw[df_raw["label"]==0].iloc[0]
attack_row = df_raw[df_raw["label"]==1].iloc[0]

normal_feats = build_request_features(
    path=normal_row["url"], payload=normal_row["payload"],
    headers={"user-agent": normal_row["user_agent"]},
    method=normal_row["method"], user_agent=normal_row["user_agent"]
)
attack_feats = build_request_features(
    path=attack_row["url"], payload=attack_row["payload"],
    headers={"user-agent": attack_row["user_agent"]},
    method=attack_row["method"], user_agent=attack_row["user_agent"]
)
print("   normal features (first 10):", {k: normal_feats[k] for k in list(normal_feats)[:10]})
print("   attack features (first 10):", {k: attack_feats[k] for k in list(attack_feats)[:10]})
print()

print("4. Are normal and attack features distinguishable?")
print(f"   url_length:        normal={normal_feats['url_length']}, attack={attack_feats['url_length']}")
print(f"   query_length:      normal={normal_feats['query_length']}, attack={attack_feats['query_length']}")
print(f"   payload_length:    normal={normal_feats['payload_length']}, attack={attack_feats['payload_length']}")
print(f"   sql_pattern_hits:  normal={normal_feats['sql_pattern_hits']}, attack={attack_feats['sql_pattern_hits']}")
print(f"   special_char_count: normal={normal_feats['special_char_count']}, attack={attack_feats['special_char_count']}")
print()

print("5. Test the UNCALIBRATED random forest if available:")
import joblib, os
if os.path.exists("rf_model.pkl"):
    rf = joblib.load("rf_model.pkl")
    print(f"   Model type: {type(rf).__name__}")
    if hasattr(rf, 'calibrated_classifiers_'):
        print(f"   It's calibrated. Base estimator: {type(rf.calibrated_classifiers_[0].estimator).__name__}")
        # Get raw predictions from base estimator
        base = rf.calibrated_classifiers_[0].estimator
        # Build the same feature row
        benign_X = pd.DataFrame([{c: normal_feats.get(c, 0) for c in feature_columns}])[feature_columns]
        attack_X = pd.DataFrame([{c: attack_feats.get(c, 0) for c in feature_columns}])[feature_columns]
        print(f"   Calibrated benign prob: {rf.predict_proba(benign_X)[0]}")
        print(f"   Uncalibrated benign prob: {base.predict_proba(benign_X)[0]}")
        print(f"   Calibrated attack prob: {rf.predict_proba(attack_X)[0]}")
        print(f"   Uncalibrated attack prob: {base.predict_proba(attack_X)[0]}")


