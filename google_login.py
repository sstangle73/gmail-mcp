"""Sign in to Google once for one mailbox, and keep the refresh token this server uses for it. Run it yourself.

    python google_login.py --account me@example.com --client-json <client_secret_....json>   consent, then a probe
    python google_login.py --account me@example.com --probe                                  probe again

The account must be in accounts.json. It opens Google's consent page (access_type=offline, so Google returns a
refresh token), listens on http://localhost:8765/callback for the answer, and writes GOOGLE_CLIENT_ID,
GOOGLE_CLIENT_SECRET and GOOGLE_REFRESH_TOKEN to data/google-<slug>.env, readable only by you. Then
python deploy.py --apply --google-file <address>=<that file> stores them in SSM, and the file and the client JSON
can go. The OAuth client must be a Web application client with http://localhost:8765/callback among its redirect
URIs, in a Google Cloud project with the Gmail API turned on.

The scope is gmail.modify (SCOPES): it reads, labels, drafts, sends, and moves to Trash and Spam. Google's scope page
says it "does not allow immediate, permanent deletion of threads and messages, bypassing the trash", and it can't
create filters or change forwarding, send-as, delegates or the vacation reply. --scopes asks for others; the script
refuses to write BROAD ones (full access, which deletes for good, and the settings scopes) unless
--allow-broad-scopes. The probe then makes read-only calls for each kind of tool and says which work.

Nothing here prints a token or the client secret.
"""
import argparse
import asyncio
import base64
import hashlib
import http.server
import json
import os
import secrets
import sys
import threading
import urllib.parse
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import accounts as accounts_  # noqa: E402

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
G = "https://www.googleapis.com/auth/"
MODIFY = G + "gmail.modify"
SCOPES = [MODIFY]
CAN_SEND = {MODIFY, G + "gmail.send", G + "gmail.compose", "https://mail.google.com/"}
BROAD = {"https://mail.google.com/", G + "gmail.settings.basic", G + "gmail.settings.sharing"}
CONSUMER = {"gmail.com", "googlemail.com"}
# Read-only calls, one for each kind of tool: what the probe makes.
PROBES = (("reading mail", "messages", {"maxResults": 1}), ("labels", "labels", None),
          ("drafts", "drafts", {"maxResults": 1}), ("the settings checks", "settings/filters", None),
          ("send-as (for the settings checks)", "settings/sendAs", None))


def read_client(path: Path) -> tuple[str, str]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    web = doc.get("web")
    if not web:
        sys.exit(f"{path} isn't a Web application client (it has {', '.join(doc) or 'nothing'}): google_login.py "
                 "needs a Web client with http://localhost:8765/callback as a redirect URI")
    return web["client_id"], web["client_secret"]


def consent(client_id: str, client_secret: str, scopes: list[str], port: int, address: str) -> dict:
    """The authorization code flow with PKCE on a loopback redirect; Google's token response."""
    import server   # for its _post (stdlib only)
    redirect = f"http://localhost:{port}/callback"
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)
    query = {"client_id": client_id, "redirect_uri": redirect, "response_type": "code", "scope": " ".join(scopes),
             "access_type": "offline", "prompt": "consent", "include_granted_scopes": "false", "login_hint": address,
             "state": state, "code_challenge": challenge, "code_challenge_method": "S256"}
    domain = address.rsplit("@", 1)[1]
    if domain not in CONSUMER:
        query["hd"] = domain   # a Workspace domain: Google offers only that domain's accounts
    url = AUTH_URL + "?" + urllib.parse.urlencode(query)
    got: dict[str, str] = {}
    done = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
            if urllib.parse.urlsplit(self.path).path != "/callback":
                self.send_response(404)
                self.end_headers()
                return
            got.update(q)
            ok = q.get("state") == state and "code" in q
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(("Signed in: go back to the terminal." if ok else
                              f"Not signed in ({q.get('error', 'state mismatch')}): see the terminal.").encode())
            done.set()

        def log_message(self, *a):   # the query string holds the code
            pass

    srv = http.server.HTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"Opening Google's consent page. Sign in as {address}. If no browser opens, visit:\n\n  {url}\n")
    webbrowser.open(url)
    if not done.wait(600):
        srv.shutdown()
        sys.exit("no answer from Google within 10 minutes")
    srv.shutdown()
    if got.get("state") != state:
        sys.exit("the answer's state didn't match: start again")
    if "code" not in got:
        sys.exit(f"Google answered {got.get('error', 'without a code')}")
    body = urllib.parse.urlencode({"code": got["code"], "client_id": client_id, "client_secret": client_secret,
                                   "redirect_uri": redirect, "grant_type": "authorization_code",
                                   "code_verifier": verifier}).encode()
    status, _, raw = server._post(server.TOKEN_URL, body, {"Content-Type": "application/x-www-form-urlencoded"})
    tokens = json.loads(raw or b"{}")
    if status != 200:
        sys.exit(f"Google refused the code: {tokens.get('error_description') or tokens.get('error') or status}")
    if not tokens.get("refresh_token"):
        sys.exit("Google returned no refresh token: revoke the app at myaccount.google.com/permissions and run this "
                 "again (prompt=consent should prevent this)")
    return tokens


def mailbox_of(access_token: str) -> str:
    """The address Google signed in, from the Gmail profile: login_hint and hd only suggest one."""
    import server
    try:
        status, _, raw = server._post(server.GMAIL_API + "/profile", None,
                                      {"Authorization": f"Bearer {access_token}"}, method="GET")
    except server.UpstreamError as e:
        sys.exit(f"nothing written: couldn't read the Gmail profile ({e})")
    if status != 200:
        sys.exit(f"nothing written: Gmail answered HTTP {status} for the profile")
    return str(json.loads(raw or b"{}").get("emailAddress") or "").strip().lower()


def write_env(path: Path, client_id: str, client_secret: str, refresh_token: str, address: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"# google_login.py: the Google sign-in this server uses for {address}. Never commit or share this,\n"
                "# and delete it once deploy.py --google-file has stored it.\n"
                f"GOOGLE_CLIENT_ID={client_id}\nGOOGLE_CLIENT_SECRET={client_secret}\n"
                f"GOOGLE_REFRESH_TOKEN={refresh_token}\n")


def probe(env_file: Path, a: dict) -> int:
    """Read-only Gmail API calls with the file's token: 'ok', or what Google said."""
    import server
    vals = server._read_env_file(env_file)
    for k in accounts_.GOOGLE:
        if not vals.get(k):
            sys.exit(f"{env_file} has no {k}: run google_login.py --account {a['address']} --client-json first")
    g = server.Gmail(server.Account(address=a["address"], slug=a["slug"], level=a["level"], sends_per_hour=0,
                                    organise_per_hour=0, client_id=vals["GOOGLE_CLIENT_ID"],
                                    client_secret=vals["GOOGLE_CLIENT_SECRET"],
                                    refresh_token=vals["GOOGLE_REFRESH_TOKEN"]))

    async def run() -> int:
        missing = 0
        for what, path, query in PROBES:
            try:
                await g.api("GET", path, query)
                print(f"  ✓ ok       {what}")
            except server.UpstreamError as e:
                missing += 1
                print(f"  ✗ REFUSED  {what}: {str(e)[:200]}")
        return missing

    missing = asyncio.run(run())
    print(f"{missing} kind(s) of call refused" if missing else "every probe worked")
    return 1 if missing else 0


def utf8_output() -> None:
    """Print UTF-8 whatever stdout is. Piped on Windows (Set-GmailMcpSignin.ps1's `| Out-Host`), Python writes in
    the locale's code page, cp1252, which has no check mark: the first probe line crashed on 2026-11-08."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def main() -> None:
    utf8_output()
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--account", required=True, help="the mailbox's address, as in accounts.json")
    ap.add_argument("--accounts-file", type=Path, default=ROOT / "accounts.json")
    ap.add_argument("--client-json", type=Path, help="the Web client's downloaded client_secret_....json")
    ap.add_argument("--out", type=Path, help="default data/google-<slug>.env")
    ap.add_argument("--scopes", help="space- or comma-separated scopes instead of gmail.modify")
    ap.add_argument("--allow-broad-scopes", action="store_true",
                    help="write the file even if a scope is broader than the tools need (BROAD)")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--probe", action="store_true", help="only probe with the file's token")
    args = ap.parse_args()
    listed = {a["address"]: a for a in accounts_.load(args.accounts_file)}
    a = listed.get(args.account.strip().lower())
    if not a:
        sys.exit(f"{args.account} isn't in {args.accounts_file}: add it there first")
    out = args.out or ROOT / "data" / f"google-{a['slug']}.env"
    if args.probe:
        sys.exit(probe(out, a))
    if not args.client_json:
        sys.exit("--client-json is needed (or --probe)")
    client_id, client_secret = read_client(args.client_json)
    scopes = args.scopes.replace(",", " ").split() if args.scopes else SCOPES
    tokens = consent(client_id, client_secret, scopes, args.port, a["address"])
    granted = sorted(tokens.get("scope", "").split())
    print("Google granted:\n  " + "\n  ".join(granted))
    broad = sorted(set(granted) & BROAD)
    if broad:
        print(f"⚠ broader than the tools need: {', '.join(broad)}")
        if not args.allow_broad_scopes:
            sys.exit("nothing written: run again without them, or with --allow-broad-scopes")
    if not set(granted) & CAN_SEND:
        print("⚠ no scope that sends: sending will fail until google_login.py is run again with one")
    signed_in = mailbox_of(tokens.get("access_token", ""))
    if signed_in != a["address"]:
        sys.exit(f"nothing written: Google signed in {signed_in or 'an unknown mailbox'}, not {a['address']}. "
                 "Run again and pick that account on Google's page")
    write_env(out, client_id, client_secret, tokens["refresh_token"], a["address"])
    print(f"written to {out} (client id, client secret, refresh token). Probing:\n")
    probe(out, a)
    print(f"\nNext: python deploy.py --apply --google-file {a['address']}={out}, then delete {out} and the client "
          "JSON.")


if __name__ == "__main__":
    main()
