"""oauth2.googleapis.com/token and the Gmail API, for several mailboxes, in one local HTTP server.

Each mailbox has its own refresh token; the access token it gets decides which mailbox a call reaches, as at Google.
"""
import base64
import http.server
import json
import threading
import time
from email import policy
from email.parser import BytesParser
from urllib.parse import parse_qs

SYSTEM = ["INBOX", "SPAM", "TRASH", "UNREAD", "STARRED", "SENT", "DRAFT", "IMPORTANT"]


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def part(mime, text=None, data=None, filename="", part_id="0", charset="utf-8", parts=None, attachment_id=None):
    headers = [{"name": "Content-Type", "value": f"{mime}; charset=\"{charset}\"" if text is not None else mime}]
    body = {"size": 0}
    if text is not None:
        raw = text.encode(charset)
        body = {"size": len(raw), "data": b64(raw)}
    if attachment_id:
        headers.append({"name": "Content-Disposition", "value": f"attachment; filename=\"{filename}\""})
        body = {"size": len(data), "attachmentId": attachment_id}
    p = {"partId": part_id, "mimeType": mime, "filename": filename, "headers": headers, "body": body}
    if parts:
        p["parts"] = parts
    return p


def payload_from_raw(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    headers = [{"name": k, "value": str(v)} for k, v in msg.items()]
    body = msg.get_body(("plain",))
    text = body.get_content() if body else ""
    return {"partId": "", "mimeType": "text/plain", "filename": "", "headers": headers,
            "body": {"size": len(text), "data": b64(text.encode())}}


class Mailbox:
    def __init__(self, address):
        self.address = address
        self.labels = [{"id": x, "name": x, "type": "system"} for x in SYSTEM]
        self.messages: dict[str, dict] = {}
        self.drafts: dict[str, dict] = {}
        self.attachments: dict[str, bytes] = {}
        self.sent: list[tuple[str, bytes, str | None]] = []
        self.settings = {"filters": {}, "autoForwarding": {"enabled": False}, "forwardingAddresses": {},
                         "sendAs": {"sendAs": [{"sendAsEmail": address, "isPrimary": True}]},
                         "vacation": {"enableAutoReply": False}, "imap": {"enabled": False},
                         "pop": {"accessWindow": "disabled"}}
        self.calls: list[tuple[str, str]] = []
        self.n = 0

    def new_id(self, stem):
        self.n += 1
        return f"{stem}{self.n}"

    def add(self, mid, thread, headers, payload_parts=None, labels=("INBOX", "UNREAD"), text=None, mime="text/plain"):
        hs = [{"name": k, "value": v} for k, v in headers.items()]
        if payload_parts:
            payload = part("multipart/mixed", parts=payload_parts)
            payload["headers"] = hs + payload["headers"]
        else:
            payload = part(mime, text or "")
            payload["headers"] = hs + payload["headers"]
        self.messages[mid] = {"id": mid, "threadId": thread, "labelIds": list(labels), "payload": payload,
                              "snippet": (text or "")[:40], "when": time.time()}
        return self.messages[mid]


class FakeGoogle:
    def __init__(self):
        self.boxes: dict[str, Mailbox] = {}     # refresh token -> mailbox
        self.secrets: dict[str, str] = {}       # refresh token -> client secret
        self.access: dict[str, Mailbox] = {}    # access token -> mailbox
        self.refresh_ok = True
        self.echoed = []
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def reply(self, status, doc=None):
                data = b"" if doc is None else json.dumps(doc).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

            def body(self):
                n = int(self.headers.get("Content-Length", 0))
                return self.rfile.read(n) if n else b""

            def do_GET(self):
                self.route("GET", b"")

            def do_POST(self):
                self.route("POST", self.body())

            def do_PUT(self):
                self.route("PUT", self.body())

            def do_PATCH(self):
                self.route("PATCH", self.body())

            def do_DELETE(self):
                self.route("DELETE", b"")

            def route(self, method, raw):
                if self.path == "/token":
                    form = parse_qs(raw.decode())
                    rt = (form.get("refresh_token") or [""])[0]
                    box = fake.boxes.get(rt)
                    if not (fake.refresh_ok and box and form.get("client_secret") == [fake.secrets[rt]]):
                        return self.reply(400, {"error": "invalid_grant",
                                                "error_description": "Token has been expired or revoked."})
                    token = f"ya29.{box.new_id('t')}-{box.address}"
                    fake.access[token] = box
                    return self.reply(200, {"access_token": token, "expires_in": 3599})
                if self.path == "/moved":
                    self.send_response(307)
                    self.send_header("Location", fake.base + "/echo")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path == "/echo":
                    fake.echoed.append(self.headers.get("Authorization"))
                    return self.reply(200, {})
                if not self.path.startswith("/gmail/"):
                    return self.reply(404, {})
                token = (self.headers.get("Authorization") or "").removeprefix("Bearer ")
                box = fake.access.get(token)
                if not box:
                    return self.reply(401, {"error": {"message": "bad token"}})
                path, _, query = self.path[len("/gmail/"):].partition("?")
                box.calls.append((method, path))
                q = {k: v for k, v in parse_qs(query).items()}
                doc = json.loads(raw) if raw else {}
                status, out = fake.gmail(box, method, path, q, doc)
                return self.reply(status, out)

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def mailbox(self, address, refresh, secret):
        box = Mailbox(address)
        self.boxes[refresh], self.secrets[refresh] = box, secret
        return box

    # The Gmail API, as much as the server uses.

    def gmail(self, box: Mailbox, method, path, q, doc):
        parts = path.split("/")
        nf = (404, {"error": {"message": "Requested entity was not found."}})
        if path == "profile":
            return 200, {"emailAddress": box.address, "messagesTotal": len(box.messages)}
        if path == "labels":
            if method == "GET":
                return 200, {"labels": box.labels}
            label = {"id": box.new_id("Label_"), "name": doc["name"], "type": "user"}
            box.labels.append(label)
            return 200, label
        if parts[0] == "labels" and len(parts) == 2:
            label = next((x for x in box.labels if x["id"] == parts[1]), None)
            if not label:
                return nf
            if method == "PATCH":
                label["name"] = doc["name"]
            return 200, label
        if path == "messages" and method == "GET":
            hits = list(box.messages.values())
            if "labelIds" in q:
                hits = [m for m in hits if q["labelIds"][0] in m["labelIds"]]
            if "q" in q and q["q"][0].startswith("after:"):
                since = int(q["q"][0].split(":")[1])
                hits = [m for m in hits if m["when"] > since]
            return 200, {"messages": [{"id": m["id"], "threadId": m["threadId"]} for m in hits]}
        if path == "messages/send":
            if getattr(self, "fail_send", False):
                return 503, {"error": {"message": "Backend Error"}}
            raw = base64.urlsafe_b64decode(doc["raw"] + "==")
            mid = box.new_id("sent")
            thread = doc.get("threadId") or box.new_id("thread")
            box.sent.append((mid, raw, doc.get("threadId")))
            box.messages[mid] = {"id": mid, "threadId": thread, "labelIds": ["SENT"],
                                 "payload": payload_from_raw(raw), "snippet": "", "when": time.time()}
            return 200, {"id": mid, "threadId": thread}
        if parts[0] == "messages" and len(parts) >= 2:
            m = box.messages.get(parts[1])
            if not m:
                return nf
            if len(parts) == 2:
                return 200, {k: v for k, v in m.items() if k != "when"}
            if parts[2] == "modify":
                m["labelIds"] = [x for x in m["labelIds"] if x not in doc.get("removeLabelIds", [])]
                m["labelIds"] += [x for x in doc.get("addLabelIds", []) if x not in m["labelIds"]]
                return 200, {"id": m["id"], "labelIds": m["labelIds"]}
            if parts[2] in ("trash", "untrash"):
                if parts[2] == "trash":
                    m["labelIds"] = [x for x in m["labelIds"] if x != "INBOX"] + ["TRASH"]
                else:
                    m["labelIds"] = [x for x in m["labelIds"] if x != "TRASH"]
                return 200, {"id": m["id"]}
            if parts[2] == "attachments":
                data = box.attachments.get(parts[3])
                return (200, {"size": len(data), "data": base64.urlsafe_b64encode(data).decode()}) if data else nf
        if path == "threads" and method == "GET":
            threads = {}
            for m in box.messages.values():
                if "TRASH" not in m["labelIds"] and "SPAM" not in m["labelIds"]:
                    threads.setdefault(m["threadId"], m)
            return 200, {"threads": [{"id": t, "snippet": m["snippet"]} for t, m in threads.items()]}
        if parts[0] == "threads" and len(parts) >= 2:
            msgs = [m for m in box.messages.values() if m["threadId"] == parts[1]]
            if not msgs:
                return nf
            if len(parts) == 2:
                return 200, {"id": parts[1], "messages": [{k: v for k, v in m.items() if k != "when"} for m in msgs]}
            for m in msgs:
                self.gmail(box, "POST", f"messages/{m['id']}/{parts[2]}", q, doc)
            return 200, {"id": parts[1]}
        if path == "drafts":
            if method == "GET":
                return 200, {"drafts": [{"id": d, "message": {"id": v["message"]["id"]}} for d, v in box.drafts.items()]}
            did = box.new_id("r-")
            box.drafts[did] = {"id": did, "message": {"id": box.new_id("dm"), "threadId": doc["message"].get(
                "threadId") or box.new_id("thread"), "raw": doc["message"]["raw"]}}
            return 200, {"id": did, "message": {"id": box.drafts[did]["message"]["id"]}}
        if parts[0] == "drafts" and len(parts) == 2:
            d = box.drafts.get(parts[1])
            if not d:
                return nf
            if method == "DELETE":
                del box.drafts[parts[1]]
                return 204, None
            if method == "PUT":
                d["message"] = {"id": box.new_id("dm"), "threadId": doc["message"].get("threadId") or
                                d["message"]["threadId"], "raw": doc["message"]["raw"]}
                return 200, {"id": d["id"], "message": {"id": d["message"]["id"]}}
            fmt = (q.get("format") or ["full"])[0]
            m = dict(d["message"])
            if fmt != "raw":
                m["payload"] = payload_from_raw(base64.urlsafe_b64decode(m.pop("raw") + "=="))
            return 200, {"id": d["id"], "message": m}
        if parts[0] == "settings":
            key = parts[1]
            return 200, box.settings.get(key, {})
        return 404, {"error": {"message": "no such path"}}
