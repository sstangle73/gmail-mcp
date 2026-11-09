"""AWS Lambda entry point: runs a Function URL request (payload format 2.0) through server.py's ASGI app.

The MCP SDK's session manager starts only once per instance, and adapters that run the app's lifespan on every
invocation (Mangum) would trip that on the second call. So the app, its lifespan and one event loop live as long as
Lambda keeps this container warm, and each invocation runs its one request on that loop.
"""
import asyncio
import base64
import logging
from urllib.parse import unquote

import server

# Lambda's root logger keeps WARNING and up unless told otherwise: keep this server's INFO lines (which tool was
# called; never what it returned) in CloudWatch, beside the WARNING lines for every change.
logging.getLogger("gmail-mcp").setLevel(logging.INFO)

_loop = asyncio.new_event_loop()
asyncio.set_event_loop(_loop)
_app = server.create_app()
_state: dict = {}


async def _start_lifespan():
    inbox, outbox = asyncio.Queue(), asyncio.Queue()
    await inbox.put({"type": "lifespan.startup"})
    task = asyncio.ensure_future(_app({"type": "lifespan", "asgi": {"version": "3.0"}, "state": _state},
                                      inbox.get, outbox.put))
    reply = await outbox.get()
    if reply["type"] != "lifespan.startup.complete":
        raise RuntimeError(f"app failed to start: {reply.get('message', reply['type'])}")
    return task   # kept, so the waiting lifespan isn't garbage-collected


_lifespan = _loop.run_until_complete(_start_lifespan())


async def _call(event: dict) -> dict:
    http = event.get("requestContext", {}).get("http")
    if not http:
        return {"statusCode": 400, "body": "expected a Function URL request"}
    raw_path = event.get("rawPath") or "/"
    headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in (event.get("headers") or {}).items()]
    if event.get("cookies"):
        headers.append((b"cookie", "; ".join(event["cookies"]).encode("latin-1")))
    body = event.get("body") or ""
    body = base64.b64decode(body) if event.get("isBase64Encoded") else body.encode("utf-8")
    host = (event.get("headers") or {}).get("host", "")
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
             "method": http["method"], "scheme": "https", "path": unquote(raw_path), "raw_path": raw_path.encode(),
             "query_string": (event.get("rawQueryString") or "").encode(), "root_path": "", "headers": headers,
             "client": (http.get("sourceIp", ""), 0), "server": (host, 443), "state": dict(_state)}

    done = asyncio.Event()
    request_sent = False

    async def receive():
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        await done.wait()   # the client is gone only once the response is complete
        return {"type": "http.disconnect"}

    status, out_headers, chunks = 500, [], []

    async def send(message):
        nonlocal status, out_headers
        if message["type"] == "http.response.start":
            status, out_headers = message["status"], message.get("headers", [])
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))

    try:
        await _app(scope, receive, send)
    finally:
        done.set()

    merged, cookies = {}, []
    for k, v in out_headers:
        name, value = k.decode("latin-1").lower(), v.decode("latin-1")
        if name == "set-cookie":
            cookies.append(value)
        else:
            merged[name] = f"{merged[name]}, {value}" if name in merged else value
    return {"statusCode": status, "headers": merged, "cookies": cookies,
            "body": base64.b64encode(b"".join(chunks)).decode("ascii"), "isBase64Encoded": True}


def handler(event, context):
    return _loop.run_until_complete(_call(event))
