"""Q15 Ledger Agent: POST /ledger {"question": "..."} -> {"answer": ...}. Run with: uvicorn ledger:app"""
import json
import os
import re
import urllib.request
from datetime import datetime, timedelta, timezone

from fastapi import Request

from app import app

BASE = os.environ.get("LEDGER_BASE", "")  # set in Render: the q-ledger-agent-server questionData URL (without &path=)
IST = timezone(timedelta(hours=5, minutes=30))
MONTHS = {m: i + 1 for i, m in enumerate(["january", "february", "march", "april", "may", "june", "july",
                                           "august", "september", "october", "november", "december"])}
_cache = {}


def _get(path):
    req = urllib.request.Request(BASE.split("&path=")[0] + "&path=" + path,
                                 headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) curl/8.0",
                                          "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read().decode()


def data():
    if "rows" not in _cache:
        rates = json.loads(_get("%2Frates"))["usd_per_unit"]
        latest = {}
        for line in _get("%2Fexport").splitlines():
            if not line.strip():
                continue
            o = json.loads(line)
            ts = datetime.fromisoformat(o["updated_at"].replace("Z", "+00:00"))
            if o["id"] not in latest or ts > latest[o["id"]][0]:
                latest[o["id"]] = (ts, o)
        rows = []
        for _, o in latest.values():
            d = datetime.fromisoformat(o["created_at"].replace("Z", "+00:00")).astimezone(IST)
            o["usd"] = o["amount"] * rates[o["currency"]]
            o["year"], o["month"], o["date"] = d.year, d.month, d.date()
            rows.append(o)
        _cache["rows"] = rows
    return _cache["rows"]


def months_in(q):
    found = set()
    for name, n in MONTHS.items():
        if re.search(r"\b" + name + r"\b", q) or re.search(r"\b" + name[:3] + r"\b", q):
            found.add(n)
    for y, m in re.findall(r"\b(20\d\d)-(\d\d)\b", q):
        found.add(int(m))
    qm = re.findall(r"\bq([1-4])\b", q)
    for x in qm:
        found.update(range(3 * int(x) - 2, 3 * int(x) + 1))
    if "first half" in q or "h1" in q:
        found.update(range(1, 7))
    return found


def answer(question):
    rows = data()
    q = question.lower()
    regions = {r["region"] for r in rows}
    products = {r["product"] for r in rows}
    sel = rows
    reg = [r for r in regions if re.search(r"\b" + r.lower() + r"\b", q)]
    if reg:
        sel = [r for r in sel if r["region"] in reg]
    prod = [p for p in products if p.lower() in q]
    if prod:
        sel = [r for r in sel if r["product"] in prod]
    cust = re.findall(r"\bc\d{3,}\b", q)
    if cust:
        sel = [r for r in sel if r["customer"].lower() in cust]
    mon = months_in(q)
    if mon:
        sel = [r for r in sel if r["month"] in mon]
    years = re.findall(r"\b(20\d\d)\b", q)
    if years:
        sel = [r for r in sel if str(r["year"]) in years]

    refund = "refund" in q
    void = re.search(r"\bvoid", q)
    count = re.search(r"how many|number of|count of|\bcount\b", q)
    units = re.search(r"\bunits?\b|quantity|\bqty\b|items sold", q)
    avg = re.search(r"average|mean|\baov\b", q)
    top = re.search(r"\b(top|best|most|highest|largest|biggest|leading|maximum|max)\b", q)
    low = re.search(r"\b(least|lowest|worst|fewest|smallest|minimum|min)\b", q)

    if refund:
        sel = [r for r in sel if r["status"] == "refunded"]
    elif void:
        sel = [r for r in sel if r["status"] == "void"]
    elif count and re.search(r"\borders?\b", q) and not re.search(r"paid|revenue|sales|sold|completed", q):
        pass  # all orders
    else:
        sel = [r for r in sel if r["status"] == "paid"]

    def measure(rs):
        if units:
            return sum(r["qty"] for r in rs)
        if count and not re.search(r"revenue|amount|value|usd|\$", q):
            return len(rs)
        return sum(r["usd"] for r in rs)

    for key, word in (("product", "product"), ("customer", "customer"), ("region", "region")):
        if re.search(r"\b" + word, q) and (top or low or re.search(r"\bwhich\b|\bwho\b", q)) and not (key == "product" and prod) and not (key == "customer" and cust) and not (key == "region" and reg):
            groups = {}
            for r in sel:
                groups.setdefault(r[key], []).append(r)
            if not groups:
                return None
            scored = {k: measure(v) for k, v in groups.items()}
            pick = min if low else max
            return pick(scored, key=lambda k: (scored[k], k) if pick is max else (scored[k], k))

    if count and re.search(r"customer", q) and not cust:
        return len({r["customer"] for r in sel})
    if avg:
        if not sel:
            return 0
        if units:
            return round(sum(r["qty"] for r in sel) / len(sel), 2)
        return round(sum(r["usd"] for r in sel) / len(sel), 2)
    val = measure(sel)
    return round(val, 2) if isinstance(val, float) else val


@app.post("/ledger")
async def ledger(request: Request):
    body = await request.json()
    return {"answer": answer(body.get("question", ""))}


@app.get("/ledger")
def ledger_warm():
    return {"rows": len(data())}
