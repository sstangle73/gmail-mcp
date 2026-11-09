"""What every copy of the server has to agree on, in one DynamoDB table: rate limits, sign-in lockout, things that
may be used once (codes, refresh tokens, authenticator steps), and the audit log of every change.

Lambda may run several copies at once, each with its own memory, so counting in memory would let each copy have its
own limit. DynamoState counts in the table with conditional writes instead. MemoryState does the same in one
process, for tests and running locally; the Lambda refuses to start without a table (server.config()).

Fails closed: when the table can't be reached, the call raises StateError, and the caller refuses the change or the
sign-in. Reading mail needs no state, so it still works.

Items (partition key pk, expiry ttl, which DynamoDB's TTL removes on its own):
  rate#<key>#<width>#<slice>  n   changes counted in one slice (a sixth) of the window
  fail#<who>#<quarter>        n   sign-in attempts in that quarter hour, by address group and "all": each attempt is
                                  counted before the password is checked, and a good one is taken back off (reserve)
  used#<sha256>                   a code, refresh token or authenticator step already used
  audit#<time>#<random>           one change: account, tool, ids, recipient domains, outcome (never subjects or bodies)
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import threading
import time
from typing import Any

AUDIT_DAYS = 90
log = logging.getLogger("gmail-mcp")


class StateError(Exception):
    """The table couldn't be reached or refused: callers refuse the change."""


def _hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


SLICES = 6


class Window:
    """The window arithmetic both stores share. A window of `seconds` is counted in SLICES slices, and a take sees
    the slice it falls in plus the SLICES before it in full. So any `seconds` span lies inside what one take sees,
    and no span of that length ever holds more than the limit; a count stops being seen between 1 and 1 1/6 windows
    after it was made. (A two-bucket estimate let about twice the limit through: security review, 2026-11-08.)"""

    @staticmethod
    def slices(now: float, seconds: int) -> tuple[int, int, list[int]]:
        """(slice width, this slice, the earlier slices a take adds up)."""
        width = max(1, seconds // SLICES)
        here = int(now // width)
        return width, here, [here - i for i in range(1, SLICES + 1)]


class MemoryState:
    def __init__(self):
        self._n: dict[str, tuple[int, float]] = {}
        self._used: dict[str, float] = {}
        self.audits: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self.down = False   # tests: behave as if the table can't be reached

    def _check(self):
        if self.down:
            raise StateError("the state table can't be reached")

    def _get(self, pk: str) -> int:
        n, exp = self._n.get(pk, (0, 0))
        return n if exp > time.time() else 0

    def take(self, key: str, limit: int, seconds: int = 3600) -> bool:
        """Count one against key's limit; False (nothing counted) when the window is full."""
        with self._lock:
            self._check()
            width, here, before = Window.slices(time.time(), seconds)
            budget = limit - sum(self._get(f"rate#{key}#{width}#{x}") for x in before)
            pk = f"rate#{key}#{width}#{here}"
            if budget <= 0 or self._get(pk) >= budget:
                return False
            self._n[pk] = (self._get(pk) + 1, (here + SLICES + 2) * width)
            return True

    def reserve(self, who: str, seconds: int, mine: int, everyone: int) -> int | None:
        """Count a sign-in attempt from who before it's checked, so guesses sent at once can't all get past a count
        that none of them has added to yet. The quarter it was counted in, or None (nothing counted) when who has
        had `mine` attempts in this quarter and the last, or everyone together `everyone`."""
        with self._lock:
            self._check()
            b = int(time.time() // seconds)
            pks = (f"fail#{who}#{b}", f"fail#all#{b}")
            for pk, limit in zip(pks, (mine, everyone)):
                if self._get(pk) + self._get(pk.rsplit("#", 1)[0] + f"#{b - 1}") >= limit:
                    return None
            for pk in pks:
                self._n[pk] = (self._get(pk) + 1, (b + 2) * seconds)
            return b

    def release(self, who: str, quarter: int, seconds: int) -> None:
        """Take a reserved attempt back off: it was a good sign-in."""
        with self._lock:
            self._check()
            for pk in (f"fail#{who}#{quarter}", f"fail#all#{quarter}"):
                self._n[pk] = (max(0, self._get(pk) - 1), (quarter + 2) * seconds)

    def use_once(self, key: str, until: float) -> bool:
        with self._lock:
            self._check()
            now = time.time()
            self._used = {k: t for k, t in self._used.items() if t > now}
            h = _hash(key)
            if h in self._used:
                return False
            self._used[h] = until
            return True

    def audit(self, entry: dict[str, Any]) -> None:
        with self._lock:
            self._check()
            self.audits.append({"at": int(time.time()), **entry})


class DynamoState:
    def __init__(self, table: str, client=None):
        import boto3
        self.table = table
        self.db = client or boto3.client("dynamodb")

    def _call(self, fn, **kw):
        """fn on the table; StateError when the table can't be reached or refuses, but a failed condition is
        raised as it is, for the caller to read as "no". (batch_get_item names its table inside RequestItems.)"""
        from botocore.exceptions import BotoCoreError, ClientError
        if fn.__name__ != "batch_get_item":
            kw["TableName"] = self.table
        try:
            return fn(**kw)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                raise
            log.warning("state table refused %s: %s", fn.__name__, e.response["Error"]["Code"])
            raise StateError(f"the state table refused ({e.response['Error']['Code']})") from None
        except BotoCoreError as e:
            log.warning("state table unreachable: %s", type(e).__name__)
            raise StateError("the state table can't be reached") from None

    def _get(self, pk: str) -> int:
        item = self._call(self.db.get_item, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item") or {}
        if int((item.get("ttl") or {}).get("N", "0")) <= time.time():   # TTL deletion can lag by hours
            return 0
        return int((item.get("n") or {}).get("N", "0"))

    def _get_many(self, pks: list[str]) -> int:
        """The sum of n over pks (expired ones count 0), read consistently in one call."""
        got = self._call(self.db.batch_get_item, RequestItems={self.table: {
            "Keys": [{"pk": {"S": pk}} for pk in pks], "ConsistentRead": True}})
        if (got.get("UnprocessedKeys") or {}).get(self.table):
            raise StateError("the state table didn't answer in full")
        total, now = 0, time.time()
        for item in (got.get("Responses") or {}).get(self.table) or []:
            if int((item.get("ttl") or {}).get("N", "0")) > now:
                total += int((item.get("n") or {}).get("N", "0"))
        return total

    def _add(self, pk: str, ttl: int, below: int | None = None, by: int = 1) -> bool:
        from botocore.exceptions import ClientError
        if below is not None and below <= 0:   # the condition below lets a first write through whatever below is
            return False
        kw: dict[str, Any] = {
            "Key": {"pk": {"S": pk}}, "UpdateExpression": "ADD n :one SET #t = :ttl",
            "ExpressionAttributeNames": {"#t": "ttl"},
            "ExpressionAttributeValues": {":one": {"N": str(by)}, ":ttl": {"N": str(ttl)}}}
        if below is not None:
            kw["ConditionExpression"] = "attribute_not_exists(n) OR n < :below"
            kw["ExpressionAttributeValues"][":below"] = {"N": str(below)}
        try:
            self._call(self.db.update_item, **kw)
            return True
        except ClientError:   # ConditionalCheckFailedException: the window is full
            return False

    def take(self, key: str, limit: int, seconds: int = 3600) -> bool:
        width, here, before = Window.slices(time.time(), seconds)
        budget = limit - self._get_many([f"rate#{key}#{width}#{x}" for x in before])
        return self._add(f"rate#{key}#{width}#{here}", (here + SLICES + 2) * width, below=budget)

    def reserve(self, who: str, seconds: int, mine: int, everyone: int) -> int | None:
        b = int(time.time() // seconds)
        ttl = (b + 2) * seconds
        if not self._add(f"fail#{who}#{b}", ttl, below=mine - self._get(f"fail#{who}#{b - 1}")):
            return None
        if not self._add(f"fail#all#{b}", ttl, below=everyone - self._get(f"fail#all#{b - 1}")):
            self._add(f"fail#{who}#{b}", ttl, by=-1)
            return None
        return b

    def release(self, who: str, quarter: int, seconds: int) -> None:
        for pk in (f"fail#{who}#{quarter}", f"fail#all#{quarter}"):
            self._add(pk, (quarter + 2) * seconds, by=-1)

    def use_once(self, key: str, until: float) -> bool:
        from botocore.exceptions import ClientError
        try:
            self._call(self.db.put_item, Item={"pk": {"S": f"used#{_hash(key)}"}, "ttl": {"N": str(int(until) + 60)}},
                       ConditionExpression="attribute_not_exists(pk) OR #t < :now",
                       ExpressionAttributeNames={"#t": "ttl"},
                       ExpressionAttributeValues={":now": {"N": str(int(time.time()))}})
            return True
        except ClientError:
            return False

    def audit(self, entry: dict[str, Any]) -> None:
        now = int(time.time())
        item = {"pk": {"S": f"audit#{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now))}#{secrets.token_hex(4)}"},
                "ttl": {"N": str(now + AUDIT_DAYS * 86400)}}
        for k, v in entry.items():
            if isinstance(v, list):
                item[k] = {"L": [{"S": str(x)} for x in v]}
            elif v is not None:
                item[k] = {"S": str(v)}
        self._call(self.db.put_item, Item=item)
