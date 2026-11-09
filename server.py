"""Gmail for Claude: an MCP server over the Gmail API, for one or more mailboxes, at a URL of its own.

Claude signs in with oauth.py (a password and an authenticator code). Each mailbox in accounts.json (accounts.py)
has its own Google sign-in, a refresh token for the gmail.modify scope, and a level that caps what the server does
in it. The tools are in tools.py; mail.py reads and builds messages; state.py holds the limits, lockout and audit log
that every copy of the server shares.

What gmail.modify can't do, the server can't either: delete anything for good (Trash keeps it 30 days), create
filters, or change forwarding, send-as, delegates, vacation replies, IMAP or POP. Those need other scopes, which
google_login.py refuses to write.

Secrets come from SSM when SSM_PREFIX is set (the Lambda, via deploy.py), else from the environment, .env and
data/google-<slug>.env. Nothing logs a token, a secret, or any mail content.
"""
from __future__ import annotations

import asyncio
import functools
import http.client
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from mcp.server.auth.provider import ProviderTokenVerifier
from mcp.server.lowlevel import Server
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import PlainTextResponse

import accounts as accounts_
import oauth
import state as state_

TOKEN_URL = "https://oauth2.googleapis.com/token"
GMAIL_API = "https://gmail.googleapis.com/gmail/v1/users/me"
SIGNIN = ("signing-key", "login-password-hash", "totp-secret")
ROOT = Path(__file__).resolve().parent

log = logging.getLogger("gmail-mcp")


@dataclass(frozen=True)
class Account:
    address: str
    slug: str
    level: str
    sends_per_hour: int
    organise_per_hour: int
    client_id: str
    client_secret: str
    refresh_token: str

    def allows(self, level: str) -> bool:
        return accounts_.LEVELS.index(self.level) >= accounts_.LEVELS.index(level)


@dataclass(frozen=True)
class Config:
    accounts: dict[str, Account]       # by address
    signin: oauth.Settings
    allowed_hosts: list[str]
    allowed_origins: list[str]


def _csv(name: str, default: str = "") -> list[str]:
    return [s.strip() for s in os.environ.get(name, default).split(",") if s.strip()]


def _read_env_file(path: str | Path) -> dict[str, str]:
    vals: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                k, sep, v = line.strip().partition("=")
                if sep and not k.startswith("#") and v.strip():
                    vals[k.strip()] = v.strip().strip("\"'")
    except FileNotFoundError:
        pass
    return vals


def _from_ssm(prefix: str, listed: list[dict]) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    """Sign-in's secrets and each account's Google sign-in, from SSM. boto3 comes with Lambda's Python runtime."""
    import boto3
    ssm = boto3.client("ssm")
    names = {f"{prefix}/{k}": ("signin", k) for k in SIGNIN}
    for a in listed:
        names.update({n: (a["slug"], k) for k, n in accounts_.ssm_names(prefix, a["slug"]).items()})
    got: dict[str, str] = {}
    keys = list(names)
    for i in range(0, len(keys), 10):   # GetParameters takes 10 names at a time
        for p in ssm.get_parameters(Names=keys[i:i + 10], WithDecryption=True)["Parameters"]:
            got[p["Name"]] = p["Value"]
    signin = {k: got.get(f"{prefix}/{k}", "") for k in SIGNIN}
    google = {a["slug"]: {k: got.get(n, "") for k, n in accounts_.ssm_names(prefix, a["slug"]).items()}
              for a in listed}
    return signin, google


def _from_env(listed: list[dict]) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    """The environment first, then .env, for sign-in; data/google-<slug>.env for each account, locally."""
    files = _read_env_file(ROOT / ".env")
    signin = {k: os.environ.get(k.upper().replace("-", "_")) or files.get(k.upper().replace("-", "_"), "")
              for k in SIGNIN}
    google = {}
    for a in listed:
        vals = _read_env_file(data_dir() / f"google-{a['slug']}.env")
        google[a["slug"]] = {n: vals.get(k, "") for k, n in accounts_.GOOGLE.items()}
    return signin, google


def data_dir() -> Path:
    return Path(os.environ.get("DATA_DIR") or ROOT / "data")


def _listed() -> list[dict]:
    text = os.environ.get("ACCOUNTS", "").strip()
    if text:
        return accounts_.parse(text)
    return accounts_.load(Path(os.environ.get("ACCOUNTS_FILE") or ROOT / "accounts.json"))


@functools.cache
def config() -> Config:
    listed = _listed()
    prefix = os.environ.get("SSM_PREFIX")
    signin_secrets, google = _from_ssm(prefix, listed) if prefix else _from_env(listed)
    held: dict[str, Account] = {}
    for a in listed:
        g = google[a["slug"]]
        missing = [k for k, n in accounts_.GOOGLE.items() if not g.get(n, "").strip()]
        if missing and a["level"] != "off":
            raise SystemExit(f"{a['address']} has no {', '.join(missing)}: run google_login.py --account "
                             f"{a['address']} (then deploy.py --google-file)")
        held[a["address"]] = Account(
            address=a["address"], slug=a["slug"], level=a["level"], sends_per_hour=a["sendsPerHour"],
            organise_per_hour=a["organisePerHour"], client_id=g.get("google-client-id", "").strip(),
            client_secret=g.get("google-client-secret", "").strip(),
            refresh_token=g.get("google-refresh-token", "").strip())
    signin = oauth.settings(signin_secrets)
    if not signin:
        raise SystemExit("sign-in isn't set up: run setup_signin.py (then deploy.py --signin-file)")
    return Config(accounts=held, signin=signin,
                  allowed_hosts=_csv("ALLOWED_HOSTS", urlsplit(signin.issuer).netloc),
                  allowed_origins=_csv("ALLOWED_ORIGINS", "https://claude.ai,https://claude.com"))


@functools.cache
def store():
    table = os.environ.get("STATE_TABLE", "").strip()
    if table:
        return state_.DynamoState(table)
    if os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        # Several copies may run at once on Lambda: limits counted in memory would be per copy.
        raise SystemExit("STATE_TABLE isn't set: deploy.py sets it")
    log.warning("no STATE_TABLE: limits, lockout and the audit log are kept in this process only")
    return state_.MemoryState()


# Google.

class UpstreamError(Exception):
    """Google refused or failed. The message is safe to show: it never carries a token."""


def _post(url: str, data: bytes | None, headers: dict[str, str], timeout: float = 30,
          method: str = "POST") -> tuple[int, str, bytes]:
    """A request that doesn't follow redirects: urllib would copy the Authorization header to wherever one points."""
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "gmail-mcp", **headers}, method=method)
    try:
        with oauth._no_redirects().open(req, timeout=timeout) as r:
            return r.status, r.headers.get("Content-Type", ""), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", "") if e.headers else "", e.read()
    except (OSError, http.client.HTTPException) as e:   # no answer: refused, reset, timed out, a bad TLS certificate
        log.warning("no answer from %s: %s", urlsplit(url).hostname, type(e).__name__)
        raise UpstreamError(f"no answer from Google ({type(e).__name__})") from None


class Gmail:
    """One mailbox through the Gmail API, with an access token from its stored refresh token."""

    def __init__(self, account: Account, token_url: str | None = None, api: str | None = None):
        self.account, self.token_url, self.api_base = account, token_url or TOKEN_URL, api or GMAIL_API
        self._token, self._expires = "", 0.0
        self._lock = asyncio.Lock()
        self.send_lock = asyncio.Lock()
        self._sent_label = ""
        self._verified = False
        self._verify_lock = asyncio.Lock()

    async def _check_mailbox(self) -> None:
        """Refuse every call until Google says the stored sign-in is this account's: a refresh token stored under the
        wrong address would otherwise read and send from another mailbox under this one's name, past its level
        and limits (security review, 2026-11-08)."""
        async with self._verify_lock:
            if self._verified:
                return
            got = str((await self.api("GET", "profile", _checked=True)).get("emailAddress") or "").strip().lower()
            if got != self.account.address:
                log.error("the stored sign-in for %s is for another mailbox", self.account.slug)
                raise UpstreamError(f"the stored Google sign-in for {self.account.address} is for another mailbox: "
                                    f"run google_login.py --account {self.account.address} again")
            self._verified = True

    async def access_token(self, renew: bool = False) -> str:
        async with self._lock:
            if renew or not self._token or self._expires - 60 < time.time():
                body = urllib.parse.urlencode({
                    "client_id": self.account.client_id, "client_secret": self.account.client_secret,
                    "refresh_token": self.account.refresh_token, "grant_type": "refresh_token"}).encode()
                status, _, raw = await asyncio.to_thread(
                    _post, self.token_url, body, {"Content-Type": "application/x-www-form-urlencoded"})
                try:
                    got = json.loads(raw)
                except ValueError:
                    got = {}
                if status != 200 or "access_token" not in got:
                    # error and error_description name the problem (invalid_grant: revoked or expired) and hold
                    # no secret.
                    reason = got.get("error_description") or got.get("error") or f"HTTP {status}"
                    log.warning("Google refused %s's refresh token: %s", self.account.slug, reason)
                    raise UpstreamError(f"Google refused the stored sign-in for {self.account.address} ({reason}): "
                                        f"run google_login.py --account {self.account.address} and deploy.py "
                                        "--google-file again")
                self._token = got["access_token"]
                self._expires = time.time() + int(got.get("expires_in", 3600))
            return self._token

    async def api(self, method: str, path: str, query: dict[str, Any] | None = None,
                  body: dict[str, Any] | None = None, _checked: bool = False) -> dict[str, Any]:
        """One Gmail API call (users/me/<path>); its JSON, or UpstreamError. A 401 renews the token once."""
        if not (_checked or self._verified):
            await self._check_mailbox()
        url = f"{self.api_base}/{path}" + (f"?{urllib.parse.urlencode(query, doseq=True)}" if query else "")
        data = json.dumps(body).encode() if body is not None else None
        for attempt in (1, 2):
            token = await self.access_token(renew=attempt == 2)
            headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
            if data is not None:
                headers["Content-Type"] = "application/json"
            status, _, raw = await asyncio.to_thread(_post, url, data, headers, 30, method)
            if status == 401 and attempt == 1:
                continue
            try:
                got = json.loads(raw or b"{}")
            except ValueError:
                got = {}
            if status not in (200, 204):
                err = got.get("error") if isinstance(got, dict) and isinstance(got.get("error"), dict) else {}
                log.warning("Gmail API %s %s for %s answered HTTP %s", method, path.split("/")[0],
                            self.account.slug, status)
                raise UpstreamError(f"Gmail answered HTTP {status}: {err.get('message') or 'no detail'}")
            return got if isinstance(got, dict) else {}
        raise AssertionError("unreachable")


@functools.cache
def gmail(address: str) -> Gmail:
    return Gmail(config().accounts[address])


# The MCP server.

class Health:
    """/healthz answers anyone with "ok"; everything else goes to the SDK app (OAuth routes, and /mcp behind it)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["path"] == "/healthz":
            return await PlainTextResponse("ok")(scope, receive, send)
        return await self.app(scope, receive, send)


def create_app():
    """The ASGI app: stateless JSON over Streamable HTTP, since each Lambda call may land in a fresh container."""
    import tools   # here, not at the top: tools imports this module
    cfg = config()
    mcp = Server("gmail-mcp", version="2.0", instructions=tools.instructions(cfg), on_list_tools=tools.list_tools,
                 on_call_tool=tools.call_tool)
    provider = oauth.Provider(cfg.signin, store())
    app = mcp.streamable_http_app(
        streamable_http_path="/mcp", stateless_http=True, json_response=True,
        transport_security=TransportSecuritySettings(allowed_hosts=cfg.allowed_hosts,
                                                     allowed_origins=cfg.allowed_origins),
        auth=provider.auth_settings(), token_verifier=ProviderTokenVerifier(provider), auth_server_provider=provider,
        custom_starlette_routes=provider.routes())
    provider.install(app)
    return Health(app)


if __name__ == "__main__":
    import uvicorn
    logging.basicConfig(level=logging.INFO)
    uvicorn.run(create_app(), host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "8000")),
                access_log=False)
