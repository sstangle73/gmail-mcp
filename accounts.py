"""The mailboxes this server holds, and what it may do in each: accounts.json locally, or the ACCOUNTS setting (the
same JSON) on Lambda, where deploy.py puts it. Standard library only, so deploy.py and google_login.py can use it.

    [{"address": "me@example.com", "level": "send", "sendsPerHour": 10, "organisePerHour": 50}, ...]

level is the most the server does in that mailbox, each including the ones before it:
    off        nothing: the account is held but refused
    read       search and read mail, drafts, labels and the settings checks
    organise   labels, archive, Trash and Spam (and taking them back)
    draft      write, change and delete its own drafts
    send       send, reply, forward and send its own drafts
sendsPerHour (default 10) and organisePerHour (default 50) are the most sends, and the most trash, spam, archive and
label removals, in any hour; every copy of the server counts against the same limits (state.py).

Each account's Google sign-in is three secrets, named by its slug (the address with every run of other characters
turned into "-"): on Lambda the SSM parameters <prefix>/accounts/<slug>/google-client-id, google-client-secret and
google-refresh-token; locally data/google-<slug>.env, which google_login.py writes.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

LEVELS = ("off", "read", "organise", "draft", "send")
GOOGLE = {"GOOGLE_CLIENT_ID": "google-client-id", "GOOGLE_CLIENT_SECRET": "google-client-secret",
          "GOOGLE_REFRESH_TOKEN": "google-refresh-token"}
ADDRESS = re.compile(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+")
MAX_ACCOUNTS = 10


def slug(address: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", address.lower()).strip("-")


def parse(text: str) -> list[dict]:
    """The accounts, checked: SystemExit naming the problem when anything is off."""
    try:
        doc = json.loads(text)
    except ValueError as e:
        raise SystemExit(f"accounts: not JSON ({e})") from None
    if not isinstance(doc, list) or not 1 <= len(doc) <= MAX_ACCOUNTS:
        raise SystemExit(f"accounts: a JSON list of 1 to {MAX_ACCOUNTS} accounts")
    out, seen = [], set()
    for i, a in enumerate(doc):
        if not isinstance(a, dict):
            raise SystemExit(f"accounts[{i}]: an object")
        extra = set(a) - {"address", "level", "sendsPerHour", "organisePerHour"}
        if extra:
            raise SystemExit(f"accounts[{i}]: unknown field(s) {', '.join(sorted(extra))}")
        address = str(a.get("address", "")).strip().lower()
        if not ADDRESS.fullmatch(address):
            raise SystemExit(f"accounts[{i}]: address must be a plain email address")
        if slug(address) in seen:
            raise SystemExit(f"accounts[{i}]: {address} is listed twice")
        level = a.get("level", "read")
        if level not in LEVELS:
            raise SystemExit(f"accounts[{i}] ({address}): level must be one of {', '.join(LEVELS)}")
        limits = {}
        for key, default, top in (("sendsPerHour", 10, 100), ("organisePerHour", 50, 1000)):
            v = a.get(key, default)
            if not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= top:
                raise SystemExit(f"accounts[{i}] ({address}): {key} must be a whole number from 0 to {top}")
            limits[key] = v
        seen.add(slug(address))
        out.append({"address": address, "slug": slug(address), "level": level, **limits})
    return out


def load(path: Path) -> list[dict]:
    if not path.exists():
        raise SystemExit(f"{path} is missing: copy accounts.example.json to it and list your mailboxes")
    return parse(path.read_text(encoding="utf-8"))


def compact(accounts: list[dict]) -> str:
    """The ACCOUNTS setting deploy.py stores: the same JSON, without slugs."""
    return json.dumps([{k: a[k] for k in ("address", "level", "sendsPerHour", "organisePerHour")} for a in accounts],
                      separators=(",", ":"))


def ssm_names(prefix: str, account_slug: str) -> dict[str, str]:
    return {k: f"{prefix}/accounts/{account_slug}/{k}" for k in GOOGLE.values()}
