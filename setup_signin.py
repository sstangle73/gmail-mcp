"""Set up sign-in: the password and authenticator code you sign in to this server with from Claude. Run it yourself.

    python setup_signin.py                    writes data/signin.env
    <password manager> | python setup_signin.py --password-stdin     no questions: for a script (below)

It asks for a new password twice, makes an authenticator (TOTP) secret and, once you say so, shows it for your app
(Bitwarden, 1Password, Aegis, Google Authenticator and the like), then checks a code from the app. It writes
LOGIN_PASSWORD_HASH, TOTP_SECRET and a new SIGNING_KEY to data/signin.env, readable only by you. Then:
  - on Lambda: python deploy.py --apply --signin-file data/signin.env, and delete the file;
  - locally: put the three in .env with PUBLIC_URL=http://localhost:8000.
Running it again makes a new password, secret and key, which signs every client out.

With --password-stdin it reads the password from the first line of stdin (a trailing CR LF and a UTF-8 BOM are
dropped), asks nothing and shows nothing secret. The script driving it then puts TOTP_SECRET from the file into its
authenticator, as otpauth://totp/<label>?secret=<TOTP_SECRET>&issuer=<label> (SHA-1, 6 digits, 30 seconds).
"""
import argparse
import getpass
import os
import secrets
import sys
from urllib.parse import quote

import oauth

TOTP = "SHA-1, 6 digits, every 30 seconds"   # what oauth.totp checks: every app's default
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "signin.env")


def ask(label: str) -> tuple[str, str]:
    """The password and TOTP secret, with the setup key shown and a code from the app checked."""
    password = getpass.getpass("New sign-in password, 12 or more characters (hidden): ")
    if len(password) < 12:
        sys.exit("too short: use 12 characters or more (one from a password manager is best)")
    if getpass.getpass("The same again (hidden): ") != password:
        sys.exit("the two didn't match: nothing written")
    secret = oauth.new_totp_secret()
    if input("Show the authenticator setup key on this screen now? [y/N] ").strip().lower() not in ("y", "yes"):
        sys.exit("nothing written: run it again when no one else can see your screen")
    label = quote(label)
    print(f"\nAdd this to your authenticator app as a setup key (time-based, {TOTP}):\n")
    print("    " + " ".join(secret[i:i + 4] for i in range(0, len(secret), 4)))
    print("\nor give an app that takes links this one:\n")
    print(f"    otpauth://totp/{label}?secret={secret}&issuer={label}&algorithm=SHA1&digits=6&period=30\n")
    for _ in range(3):
        if oauth.check_totp(secret, input("The 6-digit code your app shows now: ")) is not None:
            break
        print("That code doesn't match: check the key you entered, and that the device's clock is right.")
    else:
        sys.exit("nothing written: the app's codes didn't match")
    if sys.stdout.isatty():
        print("\033[3J\033[2J\033[H", end="")   # the setup key off the screen and out of the scrollback
    print("Your authenticator app has it. Clear this terminal's scrollback too, if it keeps one.")
    return password, secret


def from_stdin() -> tuple[str, str]:
    password = sys.stdin.buffer.readline().decode("utf-8-sig").rstrip("\r\n")
    if len(password) < 12:
        sys.exit("--password-stdin: the first line of stdin must be a password of 12 or more characters")
    return password, oauth.new_totp_secret()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=OUT, help=f"default {OUT}")
    ap.add_argument("--label", default="gmail-mcp", help="the name your authenticator app shows for it")
    ap.add_argument("--password-stdin", action="store_true",
                    help="read the password from stdin's first line and ask nothing: the caller adds TOTP_SECRET "
                         "from the file to its authenticator")
    args = ap.parse_args()
    if os.path.exists(args.out):
        sys.exit(f"{args.out} already exists: move it away first (a new one signs every client out)")

    password, secret = from_stdin() if args.password_stdin else ask(args.label)
    lines = ["# setup_signin.py's sign-in secrets: never commit or share this, and delete it once your host has them.",
             f"# TOTP_SECRET is base32, for an authenticator set to {TOTP}.",
             f"LOGIN_PASSWORD_HASH={oauth.hash_password(password)}", f"TOTP_SECRET={secret}",
             f"SIGNING_KEY={secrets.token_urlsafe(32)}"]
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    if args.password_stdin:
        print(f"LOGIN_PASSWORD_HASH, TOTP_SECRET and SIGNING_KEY written to {args.out}: add TOTP_SECRET to your "
              f"authenticator ({TOTP}), then deploy the file.")
    else:
        print(f"LOGIN_PASSWORD_HASH, TOTP_SECRET and SIGNING_KEY written to {args.out}. Next: on Lambda, python "
              f"deploy.py --apply --signin-file {args.out}; elsewhere, give your host those three and PUBLIC_URL as "
              "secrets.")


if __name__ == "__main__":
    main()
