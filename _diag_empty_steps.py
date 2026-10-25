import csv
import glob
import json
import os
import sqlite3
import sys

sys.path.insert(0, "code")
from main import DeletionAuditEngine

ROOT = os.path.dirname(os.path.abspath(__file__))
os.chdir(ROOT)
DATASET = os.path.join(ROOT, "dataset")

engine = DeletionAuditEngine(DATASET)

with open(os.path.join(DATASET, "deletion_requests.csv"), encoding="utf-8") as f:
    requests = list(csv.DictReader(f))
with open(os.path.join(DATASET, "sample_deletion_requests.csv"), encoding="utf-8") as f:
    sample_reqs = {r["case_id"]: r for r in csv.DictReader(f)}
with open(os.path.join(DATASET, "sample_output.csv"), encoding="utf-8") as f:
    sample_out = {r["case_id"]: r for r in csv.DictReader(f)}

print("=== SAMPLE 01/02/04 ===")
for cid in ["case_01", "case_02", "case_04"]:
    req = sample_reqs[cid]
    status, steps = engine.audit_request(req)
    gold = sample_out[cid]
    uid = engine.users_by_email.get(req["email"].lower())
    u = engine.users.get(uid, {})
    print(f"\n{cid} email={req['email']} uid={uid} audit_at={req['audit_at']}")
    print("  names", u.get("names"))
    print("  emails", u.get("emails"))
    print("  phones", u.get("phones"))
    print("  acct_map", engine.accts_by_user.get(uid))
    print("  pred", status, json.dumps(steps, separators=(",", ":")))
    print("  gold", gold["deletion_status"], gold["steps_json"][:180])
    matched = [
        o for o in engine.ev_obs
        if o["captured_at"] <= req["audit_at"]
        and engine.user_matches(uid, item_uid=o.get("user_id"), item_email=o.get("email"),
                                item_phone=o.get("phone"), item_name=o.get("name"),
                                item_hash=o.get("hash"))
    ]
    print("  matched obs", len(matched))
    for o in matched[:12]:
        print("   ", o.get("file_id"), o.get("system_id"), o.get("resource_id"), o.get("status"), o.get("email"), o.get("user_id"), o.get("captured_at"))

print("\n=== EMPTY-STEP AUTHORIZED CASES ===")
empty = []
obs_but_empty = []
no_obs = []
for req in requests:
    status, steps = engine.audit_request(req)
    if status == "NOT_APPLICABLE" or steps:
        continue
    uid = engine.users_by_email.get(req["email"].lower())
    matching = [
        o for o in engine.ev_obs
        if o["captured_at"] <= req["audit_at"]
        and engine.user_matches(uid, item_uid=o.get("user_id"), item_email=o.get("email"),
                                item_phone=o.get("phone"), item_name=o.get("name"),
                                item_hash=o.get("hash"))
    ]
    rec = (req["case_id"], uid, req["email"], req["audit_at"], matching, status)
    empty.append(rec)
    if matching:
        obs_but_empty.append(rec)
    else:
        no_obs.append(rec)

print("empty", len(empty), "no_obs", len(no_obs), "obs_but_empty", len(obs_but_empty))
print("\n-- observations that did not become steps --")
for cid, uid, em, audit_at, matching, status in obs_but_empty:
    print(f"\n{cid} uid={uid} email={em} audit={audit_at}")
    kinds = {}
    for o in matching:
        key = (o.get("file_id"), o.get("system_id"), o.get("status"), o.get("resource_id"), o.get("category"))
        kinds[key] = kinds.get(key, 0) + 1
        if o.get("resource_id") is None or o.get("system_id") is None:
            print("  incomplete obs", {k: o.get(k) for k in ("file_id","system_id","resource_id","status","email","user_id","name","hash")})
    for k, n in sorted(kinds.items(), key=lambda x: str(x[0]))[:20]:
        print(" ", n, k)

print("\n=== SQL TABLES ===")
for p in glob.glob("dataset/evidence/databases/*.sql"):
    con = sqlite3.connect(":memory:")
    try:
        con.executescript(open(p, encoding="utf-8", errors="ignore").read())
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        print(os.path.basename(p), tables)
    except Exception as e:
        print("ERR", p, e)

print("\n=== RAW EMAIL HITS FOR SAMPLE USERS IN EVIDENCE ===")
needles = {
    "case_01": ["amina.elmasri@gmail.com", "Amina El-Masri", "user_01", "+971 50 482 7316"],
    "case_02": ["mateo.rios@outlook.com", "user_02"],
    "case_04": ["thandiwe.n@gmail.com", "user_04", "analytics_901"],
}
for cid, nlist in needles.items():
    print(f"\n{cid}")
    for fid, info in engine.ev_manifest.items():
        path = os.path.join("dataset", info["file_path"])
        if not os.path.isfile(path):
            continue
        try:
            if path.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".webp")):
                continue
            raw = open(path, encoding="utf-8", errors="ignore").read().lower()
        except Exception:
            continue
        hits = [n for n in nlist if n.lower() in raw]
        if hits:
            print(f"  {fid} {info['file_path']} {info['captured_at']} hits={hits}")
