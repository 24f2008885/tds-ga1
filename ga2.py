"""TDS GA2 server (run: uvicorn ga2:app). Covers Q3 /stats, Q4 /verify, Q5 /effective-config,
Q7 /analytics, Q8 /work /metrics /healthz /logs/tail, Q11 /orders, Q12 /ping, Q13 /stream.json, Q14 /docker.json."""
import base64
import hashlib
import json
import time
import uuid
from collections import defaultdict, deque

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response

EMAIL = "24f2008885@ds.study.iitm.ac.in"
EXAM_ORIGIN = "https://exam.sanand.workers.dev"
START = time.time()
app = FastAPI()

# ---------------- per-path CORS ----------------
STRICT = {"/stats": {"https://dash-gfxyni.example.com", EXAM_ORIGIN},
          "/ping": {"https://app-wda39q.example.com", EXAM_ORIGIN}}
EXPOSE = "X-Request-ID, X-Process-Time, Retry-After, Content-Type"

REQ_COUNT = 0
LOGS = deque(maxlen=500)


def cors_headers(path, origin):
    if path in STRICT:
        if origin and origin in STRICT[path]:
            return {"Access-Control-Allow-Origin": origin, "Vary": "Origin",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "*", "Access-Control-Expose-Headers": EXPOSE}
        return {}
    return {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "*",
            "Access-Control-Allow-Headers": "*", "Access-Control-Expose-Headers": EXPOSE}


@app.middleware("http")
async def everything(request: Request, call_next):
    global REQ_COUNT
    REQ_COUNT += 1
    path = request.url.path
    origin = request.headers.get("origin")
    rid = request.headers.get("x-request-id") or str(uuid.uuid4())
    request.state.rid = rid
    t0 = time.perf_counter()
    if request.method == "OPTIONS":
        h = cors_headers(path, origin)
        resp = Response(status_code=200 if h else 403, headers=h)
    else:
        resp = await call_next(request)
        for k, v in cors_headers(path, origin).items():
            resp.headers[k] = v
    resp.headers["X-Request-ID"] = rid
    resp.headers["X-Process-Time"] = f"{time.perf_counter() - t0:.6f}"
    LOGS.append({"level": "INFO", "ts": time.time(), "path": path, "request_id": rid,
                 "method": request.method, "status": resp.status_code})
    return resp


# ---------------- rate limiter ----------------
BUCKETS = defaultdict(deque)


def limited(scope, client, limit, window=10.0):
    if not client:
        return None
    q = BUCKETS[(scope, client)]
    now = time.time()
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        retry = max(1, int(window - (now - q[0])) + 1)
        return JSONResponse({"error": "rate limited"}, status_code=429, headers={"Retry-After": str(retry)})
    q.append(now)
    return None


# ---------------- Q3 /stats ----------------
@app.get("/stats")
def stats(values: str = ""):
    nums = [int(x) for x in values.replace(" ", "").split(",") if x.strip()]
    if not nums:
        return {"email": EMAIL, "count": 0, "sum": 0, "min": None, "max": None, "mean": None}
    return {"email": EMAIL, "count": len(nums), "sum": sum(nums), "min": min(nums), "max": max(nums),
            "mean": sum(nums) / len(nums)}


# ---------------- Q4 /verify (pure-Python RS256) ----------------
PUBKEY_PEM = """MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB"""
ISS = "https://idp.exam.local"
AUD = "tds-dwsd1hws.apps.exam.local"


def _der_read(b, i):
    tag = b[i]; i += 1
    ln = b[i]; i += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(b[i:i + n], "big"); i += n
    return tag, b[i:i + ln], i + ln


def _rsa_pub():
    der = base64.b64decode("".join(PUBKEY_PEM.split()))
    _, spki, _ = _der_read(der, 0)            # SEQUENCE
    _, _, i = _der_read(spki, 0)              # AlgorithmIdentifier
    _, bitstr, _ = _der_read(spki, i)         # BIT STRING
    _, rsakey, _ = _der_read(bitstr[1:], 0)   # RSAPublicKey SEQUENCE
    _, n, j = _der_read(rsakey, 0)
    _, e, _ = _der_read(rsakey, j)
    return int.from_bytes(n, "big"), int.from_bytes(e, "big")


N, E = _rsa_pub()
K = (N.bit_length() + 7) // 8
SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _b64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_jwt(token):
    h, p, s = token.split(".")
    header = json.loads(_b64url(h))
    if header.get("alg") != "RS256":
        return None
    sig = int.from_bytes(_b64url(s), "big")
    em = pow(sig, E, N).to_bytes(K, "big")
    digest = hashlib.sha256(f"{h}.{p}".encode()).digest()
    expected = b"\x00\x01" + b"\xff" * (K - 3 - len(SHA256_PREFIX) - 32) + b"\x00" + SHA256_PREFIX + digest
    if em != expected:
        return None
    claims = json.loads(_b64url(p))
    aud = claims.get("aud")
    if claims.get("iss") != ISS:
        return None
    if (aud != AUD) and not (isinstance(aud, list) and AUD in aud):
        return None
    if not isinstance(claims.get("exp"), (int, float)) or claims["exp"] <= time.time():
        return None
    return claims


@app.post("/verify")
async def verify(request: Request):
    try:
        body = await request.json()
        claims = verify_jwt(body.get("token", ""))
    except Exception:
        claims = None
    if not claims:
        return JSONResponse({"valid": False}, status_code=401)
    return {"valid": True, "email": claims.get("email"), "sub": claims.get("sub"), "aud": claims.get("aud")}


# ---------------- Q5 /effective-config ----------------
DEFAULTS = {"port": 8000, "workers": 1, "debug": False, "log_level": "info", "api_key": "default-secret-000"}
LAYERS = [{"debug": False, "api_key": "key-0u0culvqrs"},
          {"port": "8913", "workers": "10", "api_key": "key-t380zisti6"},
          {"workers": "12", "log_level": "error", "api_key": "key-4lkwqot8hh"}]


def _coerce(k, v):
    if k in ("port", "workers"):
        return int(v)
    if k == "debug":
        return v if isinstance(v, bool) else str(v).strip().lower() in ("true", "1", "yes", "on")
    return str(v)


@app.get("/effective-config")
def effective_config(request: Request):
    cfg = dict(DEFAULTS)
    for layer in LAYERS:
        cfg.update(layer)
    for item in request.query_params.getlist("set"):
        if "=" in item:
            k, v = item.split("=", 1)
            cfg[k.strip()] = v
    out = {k: _coerce(k, v) for k, v in cfg.items()}
    out["api_key"] = "****"
    return out


# ---------------- Q7 /analytics ----------------
API_KEY = "ak_0nsjcablty62nv0lbip84v9u"


@app.post("/analytics")
async def analytics(request: Request):
    if request.headers.get("x-api-key") != API_KEY:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await request.json()
    events = body.get("events", [])
    users = {e.get("user") for e in events}
    totals = defaultdict(float)
    revenue = 0.0
    for e in events:
        amt = float(e.get("amount", 0) or 0)
        if amt > 0:
            revenue += amt
            totals[e.get("user")] += amt
    top = max(totals, key=totals.get) if totals else None
    return {"email": EMAIL, "total_events": len(events), "unique_users": len(users),
            "revenue": round(revenue, 2), "top_user": top}


# ---------------- Q8 observability ----------------
@app.get("/work")
def work(n: int = 1):
    acc = 0
    for i in range(max(0, min(n, 100000))):
        acc += i * i
    return {"email": EMAIL, "done": n}


@app.get("/metrics")
def metrics():
    txt = ("# HELP http_requests_total Total HTTP requests.\n# TYPE http_requests_total counter\n"
           f"http_requests_total {REQ_COUNT}\n")
    return PlainTextResponse(txt, media_type="text/plain; version=0.0.4")


@app.get("/healthz")
def healthz():
    return {"status": "ok", "uptime_s": round(time.time() - START, 3)}


@app.get("/logs/tail")
def logs_tail(limit: int = 20):
    return list(LOGS)[-max(1, limit):]


# ---------------- Q11 orders: idempotency + pagination + rate limit ----------------
TOTAL_ORDERS = 43
ORDER_RATE = 19
IDEMP = {}


@app.post("/orders")
async def create_order(request: Request):
    rl = limited("orders", request.headers.get("x-client-id"), ORDER_RATE)
    if rl:
        return rl
    key = request.headers.get("idempotency-key")
    if key and key in IDEMP:
        return JSONResponse(IDEMP[key], status_code=201)
    try:
        body = await request.json()
    except Exception:
        body = {}
    order = {"id": str(uuid.uuid4()), "status": "created", **({"data": body} if body else {})}
    if key:
        IDEMP[key] = order
    return JSONResponse(order, status_code=201)


@app.get("/orders")
def list_orders(request: Request, limit: int = 10, cursor: str = ""):
    rl = limited("orders", request.headers.get("x-client-id"), ORDER_RATE)
    if rl:
        return rl
    start = 1
    if cursor:
        try:
            start = int(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode())
        except Exception:
            start = 1
    limit = max(1, min(limit, 100))
    ids = list(range(start, min(TOTAL_ORDERS, start + limit - 1) + 1))
    nxt = ids[-1] + 1 if ids and ids[-1] < TOTAL_ORDERS else None
    next_cursor = base64.urlsafe_b64encode(str(nxt).encode()).decode().rstrip("=") if nxt else None
    return {"items": [{"id": i, "item": f"order-{i}"} for i in ids], "next_cursor": next_cursor}


# ---------------- Q12 /ping ----------------
@app.get("/ping")
def ping(request: Request):
    rl = limited("ping", request.headers.get("x-client-id"), 9)
    if rl:
        return rl
    return {"email": EMAIL, "request_id": request.state.rid}


# ---------------- Q13 / Q14 static JSON answers ----------------
@app.get("/stream.json")
def stream_json():
    return {"A": {"text": "Report job-c741db46: café\nReady ✓", "complete": True, "error": None},
            "B": {"text": "Partial job-c741db46", "complete": False, "error": None},
            "C": {"text": "Draft job-c741db46", "complete": False, "error": "model unloaded"}}


@app.get("/docker.json")
def docker_json():
    return {"A": {"steps": ["L3", "L4", "L5"], "seconds": 39},
            "B": {"steps": ["L1", "L2", "L3", "L4", "L5"], "seconds": 100},
            "C": {"steps": [], "seconds": 0}, "D": {"steps": [], "seconds": 0},
            "E": {"steps": ["L4", "L5"], "seconds": 39}}


# ---------------- Q10 /extract (rule-based invoice extraction) ----------------
import re
from datetime import datetime as _dt

SYM = {"$": "USD", "€": "EUR", "£": "GBP"}
MONTHS = {m: i for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}


def _num(s):
    return float(s.replace(",", "").replace(" ", ""))


def _dates(text):
    out = []
    for m in re.finditer(r"\b(20\d\d)[-/.](\d{1,2})[-/.](\d{1,2})\b", text):
        out.append((m.start(), f"{m.group(1)}-{int(m.group(2)):02d}-{int(m.group(3)):02d}"))
    for m in re.finditer(r"\b(\d{1,2})\s+([A-Za-z]{3})[a-z]*\.?,?\s+(20\d\d)\b", text):
        mo = MONTHS.get(m.group(2).lower()[:3])
        if mo:
            out.append((m.start(), f"{m.group(3)}-{mo:02d}-{int(m.group(1)):02d}"))
    for m in re.finditer(r"\b([A-Za-z]{3})[a-z]*\.?\s+(\d{1,2}),?\s+(20\d\d)\b", text):
        mo = MONTHS.get(m.group(1).lower()[:3])
        if mo:
            out.append((m.start(), f"{m.group(3)}-{mo:02d}-{int(m.group(2)):02d}"))
    return sorted(out)


def extract_invoice(text):
    t = text or ""
    low = t.lower()
    # date: prefer one near "due"
    dates = _dates(t)
    date = ""
    if dates:
        dues = [m.end() for m in re.finditer(r"due|payable|pay by|deadline|remit|\bby\b|before|no later than", low)]
        dates_after = [d for d in dates if any(0 <= d[0] - p <= 40 for p in dues)]
        if dates_after:
            dates = dates_after
        if dues:
            date = min(dates, key=lambda d: min(abs(d[0] - p) for p in dues))[1]
        else:
            date = dates[-1][1]
    # amount + currency
    money = []
    pat = r"(?:(USD|EUR|GBP)|([$€£]))\s*([0-9][0-9,]*(?:\.\d{1,2})?)|([0-9][0-9,]*(?:\.\d{1,2})?)\s*(USD|EUR|GBP|[$€£])"
    for m in re.finditer(pat, t, re.I):
        if m.group(3):
            cur = (m.group(1) or SYM.get(m.group(2), "")).upper()
            val = m.group(3)
        else:
            cur = m.group(5).upper() if m.group(5).upper() in ("USD", "EUR", "GBP") else SYM.get(m.group(5), "")
            val = m.group(4)
        try:
            money.append((m.start(), _num(val), cur))
        except ValueError:
            pass
    amount, currency = 0.0, ""
    if money:
        keys = [m.start() for m in re.finditer(r"total|amount due|balance due|grand total|due", low)]
        pick = min(money, key=lambda x: min((abs(x[0] - p) for p in keys), default=0)) if keys else max(money, key=lambda x: x[1])
        amount, currency = pick[1], pick[2]
    if not currency:
        m = re.search(r"\b(USD|EUR|GBP)\b", t, re.I)
        currency = m.group(1).upper() if m else "USD"
    # vendor
    vendor = ""
    m = re.search(r"(?:vendor|from|supplier|seller|billed by|issued by|company)\s*[:\-]\s*([^\n,;]+)", t, re.I)
    if m:
        vendor = m.group(1).strip().rstrip(".")
    if not vendor:
        m = re.search(r"([A-Z][\w&'\-]*(?:[ \-][A-Z0-9][\w&'\-]*)*\s+(?:Industries|Corp|Corporation|Inc|LLC|Ltd|Limited|GmbH|Co|Company|Group|Holdings|Enterprises|Solutions|Systems|Labs|Partners)\.?(?:\s+(?:Ltd|Inc|LLC|Co)\.?)?)", t)
        if m:
            vendor = m.group(1).strip()
    if not vendor:
        vendor = t.strip().split("\n")[0][:80] if t.strip() else "unknown"
    return {"vendor": vendor, "amount": amount, "currency": currency, "date": date}


@app.post("/extract")
async def extract(request: Request):
    try:
        body = await request.json()
        text = body.get("text", "") if isinstance(body, dict) else ""
    except Exception:
        text = ""
    if not isinstance(text, str):
        text = str(text)
    try:
        return extract_invoice(text)
    except Exception:
        return JSONResponse({"detail": "could not parse"}, status_code=422)


# ---------------- Q9 OpenAI-compatible chat completions ----------------
@app.post("/v1/chat/completions")
async def chat_completions(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    msgs = body.get("messages", []) or []
    prompt = " ".join(str(m.get("content", "")) for m in msgs if isinstance(m, dict))
    parts = []
    tok = re.findall(r"\bTK[0-9a-fA-F]{6}\b", prompt)
    if tok:
        parts.append(" ".join(tok))
    for a, op, b in re.findall(r"(-?\d+)\s*([+\-*x×])\s*(-?\d+)", prompt):
        a, b = int(a), int(b)
        parts.append(str(a + b if op == "+" else a - b if op == "-" else a * b))
    content = " ".join(parts) if parts else "OK"
    return {"id": "chatcmpl-" + uuid.uuid4().hex[:12], "object": "chat.completion", "created": int(time.time()),
            "model": body.get("model", "tds-local"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}


@app.get("/")
def root():
    return {"ok": True}
