"""TDS GA1 server: Q6 (/effective-config) and Q14 (/mcp) in one FastAPI app."""
import hashlib

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

EMAIL = "24f2008885@ds.study.iitm.ac.in"

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ---------------- Q6: 12-factor config precedence ----------------
DEFAULTS = {"port": 8000, "workers": 1, "debug": False, "log_level": "info", "api_key": "default-secret-000"}
YAML_LAYER = {"debug": False, "api_key": "key-0u0culvqrs"}  # config.development.yaml
DOTENV = {"APP_PORT": "8913", "NUM_WORKERS": "10", "APP_API_KEY": "key-t380zisti6"}  # .env
OS_ENV = {"APP_WORKERS": "12", "APP_LOG_LEVEL": "error", "APP_API_KEY": "key-4lkwqot8hh"}  # OS env


def env_to_config(env: dict) -> dict:
    out = {}
    for k, v in env.items():
        if k == "NUM_WORKERS":
            out["workers"] = v
        elif k.startswith("APP_"):
            out[k[4:].lower()] = v
    return out


def coerce(key, value):
    if key in ("port", "workers"):
        return int(value)
    if key == "debug":
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in ("true", "1", "yes", "on")
    return str(value)


@app.get("/effective-config")
def effective_config(request: Request):
    cfg = dict(DEFAULTS)
    for layer in (YAML_LAYER, env_to_config(DOTENV), env_to_config(OS_ENV)):
        cfg.update(layer)
    for item in request.query_params.getlist("set"):
        if "=" in item:
            k, v = item.split("=", 1)
            cfg[k.strip()] = v
    out = {k: coerce(k, v) for k, v in cfg.items()}
    out["api_key"] = "****"
    return out


# ---------------- Q14: minimal MCP server (streamable HTTP, JSON responses) ----------------
TOOL = {
    "name": "solve_challenge",
    "description": "Returns sha256(challenge:email)[:16] using the X-Exam-Challenge header.",
    "inputSchema": {"type": "object", "properties": {}, "required": []},
}


def rpc_result(id_, result):
    return {"jsonrpc": "2.0", "id": id_, "result": result}


@app.post("/mcp")
async def mcp(request: Request):
    body = await request.json()
    msgs = body if isinstance(body, list) else [body]
    replies = []
    for msg in msgs:
        method, id_ = msg.get("method"), msg.get("id")
        if id_ is None:  # notification, e.g. notifications/initialized
            continue
        if method == "initialize":
            replies.append(rpc_result(id_, {
                "protocolVersion": msg.get("params", {}).get("protocolVersion", "2025-03-26"),
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "tds-ga1", "version": "1.0.0"},
            }))
        elif method == "tools/list":
            replies.append(rpc_result(id_, {"tools": [TOOL]}))
        elif method == "tools/call":
            challenge = request.headers.get("x-exam-challenge", "")
            text = hashlib.sha256(f"{challenge}:{EMAIL}".encode()).hexdigest()[:16]
            replies.append(rpc_result(id_, {"content": [{"type": "text", "text": text}], "isError": False}))
        elif method == "ping":
            replies.append(rpc_result(id_, {}))
        else:
            replies.append({"jsonrpc": "2.0", "id": id_, "error": {"code": -32601, "message": "Method not found"}})
    if not replies:
        return Response(status_code=202)
    return JSONResponse(replies if isinstance(body, list) else replies[0])


@app.get("/mcp")
def mcp_get():
    return Response(status_code=405)


@app.get("/")
def root():
    return {"ok": True}
