"""Deploy gmail-mcp to AWS Lambda behind a Function URL. A dry run unless --apply.

    python deploy.py                                     what exists, and what --apply would change (builds the zip)
    python deploy.py --apply --signin-file data/signin.env --google-file me@example.com=data/google-me-example-com.env
                                                         the first deploy: store setup_signin.py's and google_login.py's
                                                         secrets, then create everything
    python deploy.py --apply                             after a code change, or a change to accounts.json
    python deploy.py --url                               print the connector URL, and put it on the clipboard
    python deploy.py --apply --only-role                 just the IAM role, for credentials allowed to manage IAM
    python deploy.py --apply --off                       the kill switch: every request is refused (HTTP 429)
    python deploy.py --apply --on                        and back on

Later:
    --google-file ADDRESS=FILE   a new Google sign-in for one mailbox (after google_login.py --account ADDRESS)
    --signin-file F              a new password and authenticator secret (signs every client out)
    --rotate-signing-key         sign every client out, keeping the password (this server's open drafts become
                                 the user's: they can no longer be changed or sent from here)

accounts.json (accounts.py) lists the mailboxes and their levels; it becomes the function's ACCOUNTS setting. To
turn one mailbox off, set its level to "off" and deploy.

Credentials: boto3's usual ones (AWS_PROFILE, AWS_ACCESS_KEY_ID and friends) or --profile. Region: --region, else
your AWS config's, else us-east-1. aws/deploy-policy.json is the most a deploy key needs; the role itself
(--only-role) needs credentials that may manage IAM.

What it manages, all named after --name (default gmail-mcp):
  - SSM /<name>/: signing-key, login-password-hash, totp-secret (SecureString); and per mailbox
    /<name>/accounts/<slug>/google-client-id (String), google-client-secret and google-refresh-token
    (SecureString). Nothing here prints any of them.
  - DynamoDB table <name>-state (on demand, TTL on ttl, deletion protection on): limits, lockout, the audit log.
  - IAM role <name>-lambda: its own logs, reading its own parameters, and reading and writing its own table.
  - Lambda <name> (python3.14, arm64, 256 MB, 60 s), logs kept 30 days.
  - Its Function URL (auth NONE: the server checks sign-in itself), the two public permissions a URL needs, and the
    PUBLIC_URL and ALLOWED_HOSTS that match it.
Whoever can replace the function's code can use every mailbox's refresh token through it: treat the deploy key that
way.
"""
import argparse
import base64
import hashlib
import io
import json
import re
import shutil
import secrets
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import accounts as accounts_

ROOT = Path(__file__).resolve().parent
RUNTIME, PYTHON, ARCH = "python3.14", "3.14", "arm64"
# Amazon Linux 2023 has glibc 2.34. pip doesn't widen a --platform to older manylinux tags, so each is listed.
PLATFORMS = ["manylinux_2_34_aarch64", "manylinux_2_28_aarch64", "manylinux_2_17_aarch64", "manylinux2014_aarch64"]
CODE = ("server.py", "oauth.py", "lambda_handler.py", "tools.py", "mail.py", "state.py", "accounts.py")
FUNCTION = {"Runtime": RUNTIME, "Handler": "lambda_handler.handler", "MemorySize": 256, "Timeout": 60,
            "Description": "Gmail MCP server for Claude"}
TAGS = {"managed-by": "gmail-mcp deploy.py"}
TRUST = {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}
SIGNIN = {"LOGIN_PASSWORD_HASH": "login-password-hash", "TOTP_SECRET": "totp-secret", "SIGNING_KEY": "signing-key"}


def role_policy(account, region, name):
    return {"Version": "2012-10-17", "Statement": [
        {"Sid": "ItsLogs", "Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": f"arn:aws:logs:{region}:{account}:log-group:/aws/lambda/{name}:*"},
        {"Sid": "ReadItsParameters", "Effect": "Allow", "Action": "ssm:GetParameters",
         "Resource": f"arn:aws:ssm:{region}:{account}:parameter/{name}/*"},
        {"Sid": "DecryptThemThroughSsm", "Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*",
         "Condition": {"StringEquals": {"kms:ViaService": f"ssm.{region}.amazonaws.com"}}},
        {"Sid": "ItsStateTable", "Effect": "Allow",
         "Action": ["dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"],
         "Resource": f"arn:aws:dynamodb:{region}:{account}:table/{name}-state"}]}


def code(e):
    return e.response["Error"]["Code"]


def read_env(path, wanted, check):
    """KEY=value lines from a file, by their SSM names; every wanted key must be there."""
    vals = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        k, sep, v = line.strip().partition("=")
        if sep and k in wanted and v.strip():
            vals[wanted[k]] = v.strip()
    missing = [k for k, n in wanted.items() if n not in vals]
    if missing:
        sys.exit(f"{path} has no {', '.join(missing)}")
    check(path, vals)
    return vals


def check_signin(path, vals):
    if not vals["login-password-hash"].startswith("scrypt:") or len(vals["signing-key"]) < 32:
        sys.exit(f"{path} doesn't look like setup_signin.py's: run it again")


def check_google(path, vals):
    if not vals["google-client-id"].endswith(".apps.googleusercontent.com") or len(vals["google-refresh-token"]) < 20:
        sys.exit(f"{path} doesn't look like google_login.py's: run it again")


def google_files(pairs, listed):
    """--google-file ADDRESS=FILE pairs, by slug; every address must be in accounts.json."""
    by_address = {a["address"]: a for a in listed}
    out = {}
    for pair in pairs or []:
        address, sep, path = pair.partition("=")
        address = address.strip().lower()
        if not sep or address not in by_address:
            sys.exit(f"--google-file {pair!r}: give ADDRESS=FILE, with an address in accounts.json")
        out[by_address[address]["slug"]] = (Path(path), read_env(Path(path), accounts_.GOOGLE, check_google))
    return out


def build_zip():
    out = ROOT / "build" / "lambda"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    tags = [a for p in PLATFORMS for a in ("--platform", p)]
    tags += [a for abi in (f"cp{PYTHON.replace('.', '')}", "abi3", "none") for a in ("--abi", abi)]
    subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", "--no-deps",
                    "--require-hashes", "--no-compile", "--only-binary=:all:", *tags, "--implementation", "cp",
                    "--python-version", PYTHON, "--target", str(out), "-r", str(ROOT / "requirements.txt")],
                   check=True)
    for f in CODE:
        shutil.copy2(ROOT / f, out / f)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(out.rglob("*")):
            rel = p.relative_to(out)
            # bin/ holds pip's console-script launchers, and the RECORDs hash them afresh each build; nothing reads
            # either.
            if (p.is_file() and "__pycache__" not in rel.parts and rel.parts[0] != "bin"
                    and not (rel.name == "RECORD" and rel.parent.name.endswith(".dist-info"))):
                info = zipfile.ZipInfo(rel.as_posix(), date_time=(2020, 1, 1, 0, 0, 0))   # same bytes, same hash
                info.external_attr, info.compress_type = 0o644 << 16, zipfile.ZIP_DEFLATED
                z.writestr(info, p.read_bytes())
    data = buf.getvalue()
    return data, base64.b64encode(hashlib.sha256(data).digest()).decode()


def to_clipboard(text):
    for cmd in (["clip"], ["pbcopy"], ["wl-copy"], ["xclip", "-selection", "clipboard"]):
        if shutil.which(cmd[0]):
            subprocess.run(cmd, input=text.encode("ascii"), check=True)
            return True
    return False


def session(args):
    import boto3
    s = boto3.Session(profile_name=args.profile, region_name=args.region)
    return boto3.Session(profile_name=args.profile, region_name=s.region_name or "us-east-1")


def ensure_role(iam, role, want, apply, name):
    """The Lambda's role, created or brought in line. Returns False when the credentials may not manage IAM."""
    from botocore.exceptions import ClientError
    do = "" if apply else "would "
    try:
        iam.get_role(RoleName=role)
        try:
            doc = iam.get_role_policy(RoleName=role, PolicyName=role)["PolicyDocument"]
        except ClientError as e:
            if code(e) != "NoSuchEntity":
                raise
            doc = None
        state = "same" if doc == want else "policy differs"
    except ClientError as e:
        if code(e) != "NoSuchEntity":
            raise
        state = "missing"
    if state == "same":
        print(f"IAM role {role} in place")
        return True
    print(f"{do}{'create' if state == 'missing' else 'update'} IAM role {role}")
    if not apply:
        return True
    try:
        if state == "missing":
            iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps(TRUST),
                            Tags=[{"Key": k, "Value": v} for k, v in TAGS.items()],
                            Description=f"Runs the {name} Lambda: its logs, SSM parameters and state table")
        iam.put_role_policy(RoleName=role, PolicyName=role, PolicyDocument=json.dumps(want))
    except ClientError as e:
        if code(e) not in ("AccessDenied", "AccessDeniedException"):
            raise
        return False
    return True


def ensure_table(db, table, apply):
    from botocore.exceptions import ClientError
    do = "" if apply else "would "
    try:
        t = db.describe_table(TableName=table)["Table"]
    except ClientError as e:
        if code(e) != "ResourceNotFoundException":
            raise
        t = None
    if not t:
        print(f"{do}create DynamoDB table {table} (on demand, deletion protection on)")
        if not apply:
            return
        db.create_table(TableName=table, BillingMode="PAY_PER_REQUEST", DeletionProtectionEnabled=True,
                        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                        Tags=[{"Key": k, "Value": v} for k, v in TAGS.items()])
        db.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})
    else:
        print(f"DynamoDB table {table} in place")
    ttl = db.describe_time_to_live(TableName=table)["TimeToLiveDescription"]
    if ttl.get("TimeToLiveStatus") not in ("ENABLED", "ENABLING"):
        print(f"{do}turn on TTL (attribute ttl) for {table}")
        if apply:
            db.update_time_to_live(TableName=table, TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"})


def wait(lam, name, waiter):
    lam.get_waiter(waiter).wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})


def main():
    from botocore.exceptions import ClientError
    ap = argparse.ArgumentParser(description="Deploy gmail-mcp to AWS Lambda (dry run by default).")
    ap.add_argument("--apply", action="store_true", help="make the changes")
    ap.add_argument("--accounts-file", type=Path, default=ROOT / "accounts.json")
    ap.add_argument("--google-file", action="append", metavar="ADDRESS=FILE",
                    help="store this Google sign-in (from google_login.py) for that mailbox; repeatable")
    ap.add_argument("--signin-file", type=Path, help="set up sign-in from this file (from setup_signin.py)")
    ap.add_argument("--rotate-signing-key", action="store_true", help="sign every client out")
    ap.add_argument("--url", action="store_true", help="only show the connector URL")
    ap.add_argument("--only-role", action="store_true", help="only create or update the IAM role")
    switch = ap.add_mutually_exclusive_group()
    switch.add_argument("--off", action="store_true", help="refuse every request (reserved concurrency 0)")
    switch.add_argument("--on", action="store_true", help="undo --off")
    ap.add_argument("--name", default="gmail-mcp", help="the function's name, and the stem of the others")
    ap.add_argument("--profile", help="an AWS profile (default: boto3's usual credentials)")
    ap.add_argument("--region", help="default: your AWS config's region, else us-east-1")
    args = ap.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", args.name):
        sys.exit("--name: up to 40 letters, digits, - and _")
    apply, name = args.apply, args.name
    do = "" if apply else "would "
    prefix, role, table = f"/{name}", f"{name}-lambda", f"{name}-state"

    s = session(args)
    region = s.region_name
    account = s.client("sts").get_caller_identity()["Account"]
    ssm, lam, iam, logs, db = (s.client(n) for n in ("ssm", "lambda", "iam", "logs", "dynamodb"))
    print(f"account {account}, region {region}, name {name}")

    role_arn, want = f"arn:aws:iam::{account}:role/{role}", role_policy(account, region, name)
    denied = ("these credentials may not manage IAM. Someone who may runs: python deploy.py --apply --only-role"
              f"{'' if name == 'gmail-mcp' else ' --name ' + name}")
    if args.only_role:
        if not ensure_role(iam, role, want, apply, name):
            sys.exit(denied)
        return

    function = furl = None
    try:
        function = lam.get_function(FunctionName=name)["Configuration"]
        furl = lam.get_function_url_config(FunctionName=name)["FunctionUrl"]
    except ClientError as e:
        if code(e) != "ResourceNotFoundException":
            raise

    if args.url:
        if not furl:
            sys.exit("no Function URL yet: run deploy.py --apply first")
        url = f"{furl.rstrip('/')}/mcp"
        print(f"connector URL: {url}{' (on the clipboard too)' if to_clipboard(url) else ''}. It holds no secret: "
              "Claude asks you to sign in with your password and authenticator code.")
        return

    if args.off or args.on:
        if not function:
            sys.exit("no function yet: deploy it first")
        print(f"{do}turn {name} {'OFF (every request refused)' if args.off else 'ON'}")
        if apply:
            if args.off:
                lam.put_function_concurrency(FunctionName=name, ReservedConcurrentExecutions=0)
            else:
                lam.delete_function_concurrency(FunctionName=name)
        return

    listed = accounts_.load(args.accounts_file)
    google = google_files(args.google_file, listed)
    have = {p["Name"] for page in ssm.get_paginator("describe_parameters").paginate(
        ParameterFilters=[{"Key": "Name", "Option": "BeginsWith", "Values": [prefix + "/"]}])
        for p in page["Parameters"]}

    # 1. The role, before any secret is written; and the table.
    if not ensure_role(iam, role, want, apply, name):
        sys.exit(denied)
    ensure_table(db, table, apply)

    # 2. The parameters.
    puts = []
    for a in listed:
        names = accounts_.ssm_names(prefix, a["slug"])
        if a["slug"] in google:
            vals = google[a["slug"]][1]
            puts += [(names["google-client-id"], "String", vals["google-client-id"]),
                     (names["google-client-secret"], "SecureString", vals["google-client-secret"]),
                     (names["google-refresh-token"], "SecureString", vals["google-refresh-token"])]
        elif a["level"] != "off" and not set(names.values()) <= have:
            sys.exit(f"{a['address']} has no Google sign-in in SSM yet: run google_login.py --account "
                     f"{a['address']}, then pass --google-file {a['address']}=data/google-{a['slug']}.env")
    held = {a["slug"] for a in listed}
    for n in sorted(have):
        m = re.fullmatch(re.escape(prefix) + r"/accounts/([^/]+)/.*", n)
        if m and m.group(1) not in held:
            print(f"note: {n} belongs to a mailbox no longer in accounts.json; delete it in the console")
    if args.signin_file:
        puts += [(f"{prefix}/{k}", "SecureString", v)
                 for k, v in read_env(args.signin_file, SIGNIN, check_signin).items()]
    elif args.rotate_signing_key:
        puts.append((f"{prefix}/signing-key", "SecureString", secrets.token_urlsafe(32)))
    if not args.signin_file and not {f"{prefix}/{k}" for k in SIGNIN.values()} <= have:
        sys.exit("sign-in isn't in SSM yet: run setup_signin.py, then pass --signin-file data/signin.env")
    for key, kind, value in puts:
        print(f"{do}put SSM {key} ({kind}{', new' if key not in have else ', replacing'})")
        if apply:
            ssm.put_parameter(Name=key, Type=kind, Value=value, Overwrite=key in have, Tier="Standard")
    if not puts:
        print(f"SSM {prefix}/: {len(have)} parameters in place")
    if apply:
        for path in [args.signin_file, *(p for p, _ in google.values())]:
            if path:
                print(f"{path} is in SSM now: delete it")

    # 3. The code and the function.
    zip_bytes, sha = build_zip()
    print(f"built the zip: {len(zip_bytes) // 1024} KiB, sha256 {sha[:12]}...")
    current = (function or {}).get("Environment", {}).get("Variables", {})
    variables = {"SSM_PREFIX": prefix, "STATE_TABLE": table, "ACCOUNTS": accounts_.compact(listed),
                 "PUBLIC_URL": furl.rstrip("/") if furl else "http://localhost:8000",
                 "ALLOWED_HOSTS": furl.split("/")[2] if furl else "localhost:8000",
                 # A new value makes Lambda start fresh containers, which read the changed secrets.
                 "SECRETS_VERSION": str(int(current.get("SECRETS_VERSION", "0")) + bool(puts))}
    if not function:
        print(f"{do}create Lambda function {name} ({RUNTIME}, {ARCH})")
        if apply:
            for attempt in range(15):   # a role just made takes a few seconds to be usable by Lambda
                try:
                    lam.create_function(FunctionName=name, Role=role_arn, Code={"ZipFile": zip_bytes},
                                        Architectures=[ARCH], Environment={"Variables": variables}, Tags=TAGS,
                                        **FUNCTION)
                    break
                except ClientError as e:
                    if code(e) != "InvalidParameterValueException" or attempt == 14:
                        raise
                    time.sleep(4)
            wait(lam, name, "function_active_v2")
    else:
        if function["CodeSha256"] == sha:
            print("function code unchanged")
        else:
            print(f"{do}update the function's code")
            if apply:
                lam.update_function_code(FunctionName=name, ZipFile=zip_bytes)
                wait(lam, name, "function_updated_v2")
        settings = {k: function.get(k) for k in FUNCTION}
        if settings != FUNCTION or current != variables or function["Role"] != role_arn:
            print(f"{do}update the function's settings")
            if apply:
                lam.update_function_configuration(FunctionName=name, Role=role_arn,
                                                  Environment={"Variables": variables}, **FUNCTION)
                wait(lam, name, "function_updated_v2")
        else:
            print("function settings unchanged")

    # 4. The URL and who may call it (everyone: sign-in is checked inside).
    if not furl:
        print(f"{do}create the Function URL (auth NONE)")
        if apply:
            furl = lam.create_function_url_config(FunctionName=name, AuthType="NONE", InvokeMode="BUFFERED")[
                "FunctionUrl"]
            variables["PUBLIC_URL"], variables["ALLOWED_HOSTS"] = furl.rstrip("/"), furl.split("/")[2]
            lam.update_function_configuration(FunctionName=name, Environment={"Variables": variables})
            wait(lam, name, "function_updated_v2")
    try:
        sids = {st["Sid"] for st in json.loads(lam.get_policy(FunctionName=name)["Policy"])["Statement"]}
    except ClientError as e:
        if code(e) != "ResourceNotFoundException":
            raise
        sids = set()
    for sid, extra in (("public-function-url", {"Action": "lambda:InvokeFunctionUrl", "FunctionUrlAuthType": "NONE"}),
                       ("public-function-url-invoke", {"Action": "lambda:InvokeFunction",
                                                       "InvokedViaFunctionUrl": True})):
        if sid not in sids:
            print(f"{do}allow {extra['Action']} through the URL")
            if apply:
                lam.add_permission(FunctionName=name, StatementId=sid, Principal="*", **extra)

    # 5. On or off, and log retention.
    try:
        reserved = lam.get_function_concurrency(FunctionName=name).get("ReservedConcurrentExecutions")
    except ClientError as e:
        if code(e) != "ResourceNotFoundException":
            raise
        reserved = None
    if reserved == 0:
        print(f"note: {name} is OFF (deploy.py --apply --on turns it back on)")
    group = f"/aws/lambda/{name}"
    found = [g for g in logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"] if g["logGroupName"] == group]
    if not found or found[0].get("retentionInDays") != 30:
        print(f"{do}keep {group} for 30 days")
        if apply:
            if not found:
                logs.create_log_group(logGroupName=group)
            logs.put_retention_policy(logGroupName=group, retentionInDays=30)

    if not apply:
        print("dry run: nothing changed. Run again with --apply.")
    elif furl:
        print(f"done: the connector URL is {furl.rstrip('/')}/mcp, and Claude asks you to sign in.")


if __name__ == "__main__":
    main()
