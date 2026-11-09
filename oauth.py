"""Sign-in for Claude: a one-person OAuth 2.1 authorization server, built into the MCP server.

With it on, the connector URL is plain https://<host>/mcp and holds no secret. Claude finds this server's sign-in
from its 401, identifies itself with its Client ID Metadata Document (CIMD) or registers itself (DCR), and sends you
to this server's own page. You sign in there with a password and a code from an authenticator app, and Claude gets
an access token that lasts an hour (ACCESS_TOKEN_MINUTES) and a refresh token that lasts until the sign-in does
(SIGNIN_DAYS). So a leaked URL is useless, and a leaked access token works for an hour at most.

Nothing is stored: client ids, codes and tokens are signed with SIGNING_KEY (HMAC-SHA256) and carry their own
expiry, which suits Lambda, where each call may land in a fresh container. The cost: one token can't be revoked on
its own. A new SIGNING_KEY, password or TOTP secret signs every client out at once. Used codes, used refresh tokens,
used authenticator codes and failed sign-ins go in the state table (state.py), which every copy of the server shares;
when it can't be reached, sign-in is refused.

Sign-ins go only to REDIRECT_URIS (claude.ai's and claude.com's callbacks), and CIMD documents are fetched only from
CLIENT_METADATA_HOSTS (claude.ai, claude.com), so a code can't be sent to a site of an attacker's own. It can still
reach someone else's claude.ai account: they add this URL as their own connector and send you their sign-in link.
Sign in only from a Connect you just clicked yourself; every sign-in is logged at WARNING as "SIGNED IN".
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import os
import re
import secrets
import struct
import time
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import state as state_
from mcp.server.auth.provider import (AccessToken, AuthorizationCode, AuthorizationParams, AuthorizeError,
                                      RefreshToken, RegistrationError, TokenError, construct_redirect_uri)
from mcp.server.auth.routes import build_metadata
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import InvalidRedirectUriError, InvalidScopeError, OAuthClientInformationFull, OAuthToken
from pydantic import AnyUrl
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

# claude.ai's callbacks only by default. A loopback redirect (http://localhost/callback, for Claude Code) lets any
# program on a computer start a sign-in, so it's added only on purpose, through the REDIRECT_URIS setting, and the
# sign-in page then warns that an app on this computer is asking.
REDIRECT_URIS = "https://claude.ai/api/mcp/auth_callback,https://claude.com/api/mcp/auth_callback"
LOOPBACK = {"localhost", "127.0.0.1", "::1"}
SCRYPT = {"n": 2 ** 15, "r": 8, "p": 1}
REQUEST_SECONDS, CODE_SECONDS = 600, 300
# Failed sign-ins in the last 15 to 30 minutes (this quarter hour and the last): 5 from one address (an IPv6 /64
# counts as one) locks it out; 20 from everywhere locks everyone out. Counted in the shared state table, so every copy
# of the server sees the same counts.
LOCKOUT_FAILURES, LOCKOUT_SECONDS, LOCKOUT_ALL = 5, 900, 20
METADATA_MISS_SECONDS, METADATA_CACHE_MAX = 300, 64
METADATA_PATH = "/.well-known/oauth-authorization-server"
RESOURCE_PATH = "/.well-known/oauth-protected-resource"

log = logging.getLogger("gmail-mcp")


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# The password: scrypt, stored as scrypt:<n>:<r>:<p>:<salt>:<hash> (no $, which env files can expand).

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode(), salt=salt, maxmem=2 ** 26, dklen=32, **SCRYPT)
    return f"scrypt:{SCRYPT['n']}:{SCRYPT['r']}:{SCRYPT['p']}:{_b64(salt)}:{_b64(key)}"


def _parse_hash(stored: str) -> tuple[dict[str, int], bytes, bytes]:
    kind, n, r, p, salt, key = stored.strip().split(":")
    if kind != "scrypt":
        raise ValueError(kind)
    return {"n": int(n), "r": int(r), "p": int(p)}, _unb64(salt), _unb64(key)


def check_password(password: str, stored: str) -> bool:
    cost, salt, key = _parse_hash(stored)
    got = hashlib.scrypt(password.encode(), salt=salt, maxmem=2 ** 26, dklen=len(key), **cost)
    return hmac.compare_digest(got, key)


# The authenticator code: RFC 6238 TOTP, the defaults every app uses (SHA-1, 6 digits, 30 seconds).

def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


def totp(secret: str, step: int) -> str:
    key = base64.b32decode(secret.strip().upper() + "=" * (-len(secret.strip()) % 8))
    mac = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    off = mac[-1] & 15
    return f"{(struct.unpack('>I', mac[off:off + 4])[0] & 0x7FFFFFFF) % 10 ** 6:06d}"


def check_totp(secret: str, code: str, now: float | None = None) -> int | None:
    """The time step the code is for, allowing one step of clock drift each way; None if it's wrong."""
    code = re.sub(r"\s", "", code)
    if not re.fullmatch(r"[0-9]{6}", code):   # not \d: other scripts' digits would crash compare_digest
        return None
    t = int((time.time() if now is None else now) // 30)
    for step in (t, t - 1, t + 1):
        if hmac.compare_digest(totp(secret, step), code):
            return step
    return None


@dataclass(frozen=True)
class Settings:
    issuer: str                      # https://<host>, no path: the MCP endpoint is <issuer>/mcp
    signing_key: str
    password_hash: str
    totp_secret: str
    redirect_uris: tuple[str, ...]
    metadata_hosts: frozenset[str]
    access_seconds: int
    signin_days: int
    service_name: str = "Gmail for Claude"

    @property
    def resource(self) -> str:
        return self.issuer + "/mcp"


def settings(secrets_: dict[str, str]) -> Settings | None:
    """Sign-in's settings, or None when it's off. Secrets come in as signing-key, login-password-hash and
    totp-secret (from the environment or SSM); the rest from the environment."""
    keys = ("signing-key", "login-password-hash", "totp-secret")
    got = {k: (secrets_.get(k) or "").strip() for k in keys}
    if not any(got.values()):
        return None
    if not all(got.values()):
        raise SystemExit("sign-in needs all of SIGNING_KEY, LOGIN_PASSWORD_HASH and TOTP_SECRET (setup_signin.py "
                         "makes them); missing: " + ", ".join(k.upper().replace("-", "_") for k, v in got.items()
                                                               if not v))
    public = os.environ.get("PUBLIC_URL", "").strip().rstrip("/")
    u = urlsplit(public)
    local = u.scheme == "http" and u.hostname in LOOPBACK
    if not (u.scheme == "https" or local) or not u.hostname or u.path or u.query or u.fragment:
        raise SystemExit("sign-in needs PUBLIC_URL: this server's https:// address with no path, such as "
                         "https://gmail.example.com")
    if len(got["signing-key"]) < 32:
        raise SystemExit("SIGNING_KEY must be 32+ random characters")
    try:
        _parse_hash(got["login-password-hash"])
        totp(got["totp-secret"], 0)
    except (ValueError, TypeError) as e:
        raise SystemExit(f"LOGIN_PASSWORD_HASH or TOTP_SECRET is malformed ({type(e).__name__}): run "
                         "setup_signin.py again") from None
    uris = tuple(s.strip() for s in os.environ.get("REDIRECT_URIS", REDIRECT_URIS).split(",") if s.strip())
    hosts = frozenset(s.strip().lower() for s in os.environ.get("CLIENT_METADATA_HOSTS", "claude.ai,claude.com").split(",")
                      if s.strip())
    return Settings(issuer=public, signing_key=got["signing-key"], password_hash=got["login-password-hash"],
                    totp_secret=got["totp-secret"], redirect_uris=uris, metadata_hosts=hosts,
                    access_seconds=60 * int(os.environ.get("ACCESS_TOKEN_MINUTES", "60")),
                    signin_days=int(os.environ.get("SIGNIN_DAYS", "30")),
                    service_name=os.environ.get("SERVICE_NAME", "Gmail for Claude").strip()[:60] or "Gmail for Claude")


class Signer:
    """Signed, expiring blobs: base64url(JSON).base64url(HMAC-SHA256). The typ keeps one kind from passing as
    another (a code as a token, say)."""

    def __init__(self, key: bytes):
        self.key = key

    def _mac(self, payload: str) -> str:
        return _b64(hmac.new(self.key, payload.encode(), hashlib.sha256).digest())

    def seal(self, typ: str, body: dict[str, Any], ttl: int | None) -> str:
        data = {"typ": typ, **body}
        if ttl is not None:
            data["exp"] = int(time.time()) + ttl
        payload = _b64(json.dumps(data, separators=(",", ":")).encode())
        return f"{payload}.{self._mac(payload)}"

    def open(self, typ: str, blob: str) -> dict[str, Any] | None:
        payload, _, mac = blob.partition(".")
        if not payload or not hmac.compare_digest(mac.encode(), self._mac(payload).encode()):
            return None
        try:
            data = json.loads(_unb64(payload))
        except ValueError:
            return None
        if data.get("typ") != typ or ("exp" in data and data["exp"] < time.time()):
            return None
        return data


def _redirect_matches(want: str, registered: str) -> bool:
    """Exact, except that a loopback redirect matches on any port (RFC 8252 7.3): Claude Code picks one per run."""
    w, r = urlsplit(want), urlsplit(registered)
    if w.scheme == "http" and w.hostname in LOOPBACK:
        return (r.scheme, r.hostname, r.path or "/", r.query) == ("http", w.hostname, w.path or "/", w.query)
    return want == registered


class Client(OAuthClientInformationFull):
    """A registered client, with the loopback rule above and any scope (there's one kind of access here)."""

    def validate_redirect_uri(self, redirect_uri: AnyUrl | None) -> AnyUrl:
        if redirect_uri is not None and any(_redirect_matches(str(redirect_uri), str(r))
                                            for r in self.redirect_uris or []):
            return redirect_uri
        if redirect_uri is None and self.redirect_uris and len(self.redirect_uris) == 1:
            return self.redirect_uris[0]
        raise InvalidRedirectUriError(f"Redirect URI '{redirect_uri}' not registered for client")

    def validate_scope(self, requested_scope: str | None) -> list[str]:
        scopes = (requested_scope or "").split()
        if len(scopes) > 10 or any(len(s) > 64 for s in scopes):
            raise InvalidScopeError("too many scopes")
        return scopes


def _address_group(host: str) -> str:
    """What failed sign-ins are counted by: the IPv4 address, or the IPv6 /64 (one customer's whole block)."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host[:64]
    if ip.version == 6:
        if ip.ipv4_mapped:
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


def _no_redirects() -> urllib.request.OpenerDirector:
    class Refuse(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None
    return urllib.request.build_opener(Refuse)


def _fetch_json(url: str) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "gmail-mcp"})
    with _no_redirects().open(req, timeout=5) as r:
        if r.status != 200:
            raise ValueError(f"HTTP {r.status}")
        return json.loads(r.read(16 * 1024 + 1)[:16 * 1024])


class Provider:
    """The MCP SDK's OAuthAuthorizationServerProvider, keeping no state; and the sign-in page."""


    def __init__(self, s: Settings, store, auth_token: str | None = None):
        self.s, self.store = s, store
        root = s.signing_key.encode()
        self.clients = Signer(hmac.new(root, b"clients", hashlib.sha256).digest())
        # Tokens hang off the password and TOTP secret too, so changing either signs every client out.
        self.tokens = Signer(hmac.new(root, b"tokens\0" + s.password_hash.encode() + b"\0" + s.totp_secret.encode(),
                                      hashlib.sha256).digest())
        self.static_token = auth_token.encode() if auth_token else None
        self._metadata_clients: dict[str, tuple[float, Client | None]] = {}

    def auth_settings(self) -> AuthSettings:
        return AuthSettings(issuer_url=self.s.issuer, resource_server_url=self.s.resource, validate_token_resource=True,
                            client_registration_options=ClientRegistrationOptions(enabled=True),
                            revocation_options=RevocationOptions(enabled=False))

    def allowed_redirect(self, uri: str) -> bool:
        return any(_redirect_matches(uri, r) for r in self.s.redirect_uris)

    async def _use(self, key: str, until: float) -> bool:
        """Mark a code, refresh token or TOTP step used; False if it already was. StateError when the state table
        can't be reached."""
        return await asyncio.to_thread(self.store.use_once, key, until)

    async def _use_or_refuse(self, key: str, until: float, what: str) -> None:
        try:
            ok = await self._use(key, until)
        except state_.StateError:
            raise TokenError("invalid_grant", "sign-in is unavailable for a moment: try again") from None
        if not ok:
            raise TokenError("invalid_grant", f"{what} already used")

    # Clients: a DCR client's id is its own signed registration; a CIMD client's id is its document's URL.

    def _client_secret(self, client_id: str) -> str:
        return _b64(hmac.new(self.clients.key, b"secret\0" + client_id.encode(), hashlib.sha256).digest())

    async def get_client(self, client_id: str) -> Client | None:
        if client_id.startswith("https://"):
            return await self._metadata_client(client_id)
        b = self.clients.open("client", client_id)
        if not b:
            return None
        return Client(client_id=client_id, redirect_uris=b["r"], token_endpoint_auth_method=b["m"],
                      grant_types=b["g"], response_types=["code"], client_name=b.get("n") or None,
                      client_id_issued_at=b.get("iat"), client_secret=None if b["m"] == "none" else
                      self._client_secret(client_id), client_secret_expires_at=None if b["m"] == "none" else 0)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        uris = [str(u) for u in client_info.redirect_uris or []]
        if not uris or len(uris) > 5 or not all(self.allowed_redirect(u) for u in uris):
            raise RegistrationError("invalid_redirect_uri", "this server signs in only for " +
                                    ", ".join(self.s.redirect_uris) + " (REDIRECT_URIS)")
        method = client_info.token_endpoint_auth_method or "client_secret_post"
        # The SDK made a random id and secret and returns this same object: swap in ones that need no storage.
        client_info.client_id = self.clients.seal("client", {
            "r": uris, "m": method, "g": list(client_info.grant_types), "n": (client_info.client_name or "")[:60],
            "iat": client_info.client_id_issued_at}, None)
        if client_info.client_secret is not None:
            client_info.client_secret = self._client_secret(client_info.client_id)

    async def _metadata_client(self, url: str) -> Client | None:
        now = time.time()
        hit = self._metadata_clients.get(url)
        if hit and hit[0] > now:
            return hit[1]
        u = urlsplit(url)
        if (u.scheme != "https" or (u.hostname or "") not in self.s.metadata_hosts or u.port or u.username
                or u.fragment):
            log.warning("client metadata from %r refused: not in CLIENT_METADATA_HOSTS", u.hostname)
            return None
        # A miss is remembered too, so made-up URLs on an allowed host can't keep this fetching; the cache is capped.
        self._metadata_clients = {k: v for k, v in self._metadata_clients.items() if v[0] > now}
        if len(self._metadata_clients) >= METADATA_CACHE_MAX:   # forget the misses, never a real client
            self._metadata_clients = {k: v for k, v in self._metadata_clients.items() if v[1] is not None}
        try:
            doc = await asyncio.to_thread(_fetch_json, url)
        except Exception as e:
            log.warning("client metadata %r unreadable: %s", url[:200], type(e).__name__)
            self._metadata_clients[url] = (now + METADATA_MISS_SECONDS, None)
            return None
        uris = [r for r in doc.get("redirect_uris") or [] if isinstance(r, str) and self.allowed_redirect(r)]
        if doc.get("client_id") != url or doc.get("token_endpoint_auth_method", "none") != "none" or not uris:
            log.warning("client metadata %r refused: wrong client_id, not a public client, or no allowed redirect",
                        url[:200])
            self._metadata_clients[url] = (now + METADATA_MISS_SECONDS, None)
            return None
        grants = [g for g in doc.get("grant_types") or ["authorization_code"]
                  if g in ("authorization_code", "refresh_token")]
        client = Client(client_id=url, redirect_uris=uris, token_endpoint_auth_method="none", grant_types=grants,
                        response_types=["code"], client_name=str(doc.get("client_name") or u.hostname)[:60])
        self._metadata_clients[url] = (time.time() + 3600, client)
        return client

    # The authorization code flow.

    async def authorize(self, client: Client, params: AuthorizationParams) -> str:
        if params.resource and params.resource.rstrip("/") != self.s.resource:
            raise AuthorizeError("invalid_target", f"this server issues tokens only for {self.s.resource}")
        if not self.allowed_redirect(str(params.redirect_uri)):
            raise AuthorizeError("invalid_request", "redirect_uri is not in REDIRECT_URIS")
        req = self.tokens.seal("signin", {
            "cid": client.client_id, "ru": str(params.redirect_uri), "rx": params.redirect_uri_provided_explicitly,
            "cc": params.code_challenge, "st": params.state, "sc": params.scopes or []}, REQUEST_SECONDS)
        return f"{self.s.issuer}/signin?request={req}"

    async def load_authorization_code(self, client: Client, authorization_code: str) -> AuthorizationCode | None:
        b = self.tokens.open("code", authorization_code)
        if not b or b["cid"] != client.client_id:
            return None
        return AuthorizationCode(code=authorization_code, scopes=b["sc"], expires_at=b["exp"], client_id=b["cid"],
                                 code_challenge=b["cc"], redirect_uri=AnyUrl(b["ru"]),
                                 redirect_uri_provided_explicitly=b["rx"], resource=self.s.resource)

    async def exchange_authorization_code(self, client: Client, authorization_code: AuthorizationCode) -> OAuthToken:
        b = self.tokens.open("code", authorization_code.code)
        if not b:
            raise TokenError("invalid_grant", "authorization code isn't valid")
        await self._use_or_refuse("code:" + b["jti"], b["exp"], "authorization code")
        return self._issue(client.client_id, authorization_code.scopes, b["at"])

    async def load_refresh_token(self, client: Client, refresh_token: str) -> RefreshToken | None:
        b = self.tokens.open("refresh", refresh_token)
        if not b or b["cid"] != client.client_id:
            return None
        return RefreshToken(token=refresh_token, client_id=b["cid"], scopes=b["sc"], expires_at=b["exp"],
                            resource=self.s.resource)

    async def exchange_refresh_token(self, client: Client, refresh_token: RefreshToken,
                                     scopes: list[str]) -> OAuthToken:
        b = self.tokens.open("refresh", refresh_token.token)
        if not b:
            raise TokenError("invalid_grant", "refresh token isn't valid")
        await self._use_or_refuse("refresh:" + b["jti"], b["exp"], "refresh token")
        return self._issue(client.client_id, scopes, b["at"])

    def _issue(self, client_id: str, scopes: list[str], signed_in_at: int) -> OAuthToken:
        """An access token, and a rotated refresh token that ends when the sign-in does (SIGNIN_DAYS after it)."""
        left = signed_in_at + self.s.signin_days * 86400 - int(time.time())
        if left <= 0:
            raise TokenError("invalid_grant", "the sign-in has expired: sign in again")
        body = {"cid": client_id, "sc": scopes, "at": signed_in_at}
        ttl = min(self.s.access_seconds, left)
        return OAuthToken(access_token=self.tokens.seal("access", body, ttl), token_type="Bearer", expires_in=ttl,
                          refresh_token=self.tokens.seal("refresh", {**body, "jti": secrets.token_urlsafe(9)}, left),
                          scope=" ".join(scopes) or None)

    async def load_access_token(self, token: str) -> AccessToken | None:
        if self.static_token and hmac.compare_digest(token.encode(), self.static_token):
            return AccessToken(token=token, client_id="auth-token", scopes=[], resource=self.s.resource)
        b = self.tokens.open("access", token)
        if not b:
            return None
        return AccessToken(token=token, client_id=b["cid"], scopes=b["sc"], expires_at=b["exp"],
                           resource=self.s.resource, subject="owner")

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        """Not offered (revocation_options off): a signed token can't be revoked without storage."""

    # The routes: the sign-in page, and authorization server metadata that also offers CIMD.

    def routes(self) -> list[Route]:
        return [Route("/signin", self.signin, methods=["GET", "POST"])]

    def install(self, app) -> None:
        """Swap the SDK's metadata route for one advertising CIMD, which Claude uses only when the metadata says
        client_id_metadata_document_supported and accepts public clients ("none"). And serve the protected resource
        metadata at the root as well as at /.well-known/oauth-protected-resource/mcp: Lambda Function URLs rename the
        401's WWW-Authenticate header (x-amzn-Remapped-www-authenticate), so clients find sign-in by probing those two
        paths instead, path-suffixed first."""
        settings_ = self.auth_settings()
        m = build_metadata(settings_.issuer_url, None, settings_.client_registration_options,
                           settings_.revocation_options)
        m.token_endpoint_auth_methods_supported = ["none", "client_secret_post", "client_secret_basic"]
        m.client_id_metadata_document_supported = True
        doc = m.model_dump(mode="json", exclude_none=True)

        async def metadata(request: Request) -> Response:
            return JSONResponse(doc, headers={"Access-Control-Allow-Origin": "*", "Cache-Control": "max-age=300"})
        app.router.routes = [Route(METADATA_PATH, metadata, methods=["GET", "OPTIONS"])
                             if getattr(r, "path", None) == METADATA_PATH else r for r in app.router.routes]
        prm = next(r for r in app.router.routes if getattr(r, "path", "").startswith(RESOURCE_PATH + "/"))
        app.router.routes.append(Route(RESOURCE_PATH, prm.endpoint, methods=["GET", "OPTIONS"]))

    async def signin(self, request: Request) -> Response:
        form = await request.form() if request.method == "POST" else request.query_params
        blob = str(form.get("request") or "")
        req = self.tokens.open("signin", blob)
        client = await self.get_client(req["cid"]) if req else None
        if not req or not client:
            return self._page(None, None, "This sign-in link has expired or isn't valid. Start again from Claude.",
                              400)
        if request.method == "GET":
            return self._page(blob, req, None, 200)
        ip = _address_group(request.client.host if request.client else "")
        try:
            # The attempt is counted before the password is checked, and taken back off only when it was right: a
            # check first and a count after would let guesses sent at once all through (security review, 2026-11-08).
            quarter = await asyncio.to_thread(self.store.reserve, ip, LOCKOUT_SECONDS, LOCKOUT_FAILURES, LOCKOUT_ALL)
            if quarter is None:
                log.warning("sign-in refused from %r: locked out", ip)
                return self._page(blob, req, "Too many failed sign-ins. Try again in half an hour.", 429)
            ok = await asyncio.to_thread(check_password, str(form.get("password") or ""), self.s.password_hash)
            step = check_totp(self.s.totp_secret, str(form.get("code") or ""))
            if not ok or step is None or not await self._use(f"totp:{step}", time.time() + 120):
                log.warning("failed sign-in from %r", ip)
                return self._page(blob, req, "Wrong password or code.", 401)
        except state_.StateError:
            log.warning("sign-in refused from %r: the state table can't be reached", ip)
            return self._page(blob, req, "Sign-in is unavailable for a moment. Try again shortly.", 503)
        try:
            await asyncio.to_thread(self.store.release, ip, quarter, LOCKOUT_SECONDS)
        except state_.StateError:
            log.warning("a good sign-in from %r stays counted as an attempt: the state table can't be reached", ip)
        code = self.tokens.seal("code", {"cid": req["cid"], "ru": req["ru"], "rx": req["rx"], "cc": req["cc"],
                                         "sc": req["sc"], "at": int(time.time()), "jti": secrets.token_urlsafe(9)},
                                CODE_SECONDS)
        # WARNING, so it's kept whatever the log level: every sign-in should be one the owner made.
        log.warning("SIGNED IN: %r from %r, back to %r", req["cid"][:200], ip, urlsplit(req["ru"]).hostname)
        return RedirectResponse(construct_redirect_uri(req["ru"], code=code, state=req["st"]), status_code=303,
                                headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})

    def _page(self, blob: str | None, req: dict[str, Any] | None, error: str | None, status: int) -> HTMLResponse:
        e = html.escape
        body, origin = "", ""
        if req:
            u = urlsplit(req["ru"])
            origin = f"{u.scheme}://{u.netloc}"
            cid = req["cid"]
            who = (f"<strong>{e(urlsplit(cid).hostname or '')}</strong>" if cid.startswith("https://") else
                   "An app that registered itself here")
            if u.hostname in LOOPBACK:
                back = (f"an app on this computer (<strong>{e(u.netloc)}</strong>). Continue only if you just "
                        "connected this server from Claude Code: any program here could be asking.")
            else:
                back = f"<strong>{e(u.hostname or '')}</strong>."
            body = f"""
<p>{who} is asking to use <strong>{e(self.s.service_name)}</strong>: it reads, labels, drafts, files and sends
mail in the Gmail mailboxes this server holds.</p>
<p>When you sign in, you go back to {back}</p>
<form method="post" action="/signin">
<input type="hidden" name="request" value="{e(blob or '')}">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
<label for="code">Code from your authenticator app</label>
<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{{6,7}}" maxlength="7"
 required>
<button type="submit">Sign in</button>
</form>
<p class="small">Didn't start this from Claude? Close this page.</p>"""
        alert = f'<p class="error" role="alert"><span aria-hidden="true">✗ </span>{e(error)}</p>' if error else ""
        page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Sign in: {e(self.s.service_name)}</title>
<style>
:root {{ --bg: #ffffff; --fg: #1f2328; --muted: #59636e; --line: #d1d9e0; --accent: #0b5cad; --alert: #6f3a00; }}
@media (prefers-color-scheme: dark) {{
  :root {{ --bg: #15181c; --fg: #e6e8eb; --muted: #9aa4ae; --line: #3a4048; --accent: #6cb6ff; --alert: #ffcf8a; }}
}}
body {{ margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.5 system-ui, sans-serif; }}
main {{ max-width: 26rem; margin: 3rem auto; padding: 0 16px; }}
h1 {{ font-size: 1.4rem; }}
label {{ display: block; margin-top: 1rem; font-weight: 600; }}
input {{ box-sizing: border-box; width: 100%; padding: .6rem; margin-top: .3rem; font: inherit; color: inherit;
  background: transparent; border: 1px solid var(--line); border-radius: 6px; }}
button {{ margin-top: 1.4rem; width: 100%; padding: .7rem; font: inherit; font-weight: 600; color: var(--bg);
  background: var(--accent); border: 0; border-radius: 6px; cursor: pointer; }}
.error {{ color: var(--alert); border: 2px solid currentColor; border-radius: 6px; padding: .5rem .7rem;
  font-weight: 600; }}
.small {{ color: var(--muted); font-size: .9rem; margin-top: 1.5rem; }}
</style></head>
<body><main><h1>Sign in to {e(self.s.service_name)}</h1>{alert}{body}</main></body></html>"""
        csp = (f"default-src 'none'; style-src 'unsafe-inline'; form-action 'self' {origin}; frame-ancestors 'none'; "
               "base-uri 'none'")
        return HTMLResponse(page, status_code=status, headers={
            "Content-Security-Policy": csp, "X-Frame-Options": "DENY", "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer"})
