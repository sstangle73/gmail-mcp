# gmail-mcp

**An MCP server that gives Claude your Gmail mailboxes through the Gmail API, one sign-in for all of them, with guards that hold even when a message tries to talk Claude into something.** It runs on AWS Lambda behind a Function URL, and claude.ai connects to it as a custom connector.

- **Several mailboxes, one connector.** `accounts.json` lists them. Every tool takes `account`, so each approval prompt shows which mailbox. Each mailbox has its own Google sign-in, level and limits.
- **Levels:** `read` < `organise` < `draft` < `send` (or `off`). The server refuses anything above a mailbox's level.
- **Scope:** `gmail.modify` only. It can't delete mail for good, create filters, or change forwarding, send-as, delegates, the vacation reply, IMAP or POP. The server can't either. The one thing it removes for good is a draft the server itself made (`delete_draft`, and `send_draft` once the draft is sent): Gmail has no trash for drafts. `check_settings` reads those settings, so Claude can look for what an intruder would have changed.

## Tools

| Level | Tools |
|---|---|
| read | `search_threads`, `get_thread`, `get_message`, `get_attachment` (text types only), `list_labels`, `list_drafts`, `get_draft`, `check_settings` |
| organise | `create_label`, `update_label`, `label_` / `unlabel_` / `archive_` / `trash_` / `untrash_` (message or thread), `mark_..._spam` / `unmark_..._spam`, `update_message_labels` |
| draft | `create_draft`, `update_draft`, `delete_draft` (only the server's own drafts), `adopt_draft` (takes over one of yours) |
| send | `send_message`, `reply`, `forward_message`, `send_draft` |

## Guards

Every call passes these, and the server refuses at the first one that fails:

1. **Strict arguments.** Only the arguments the tool's schema lists, of the right types. Ids must look like ids.
2. **The mailbox's level.** A call above it is refused.
3. **The right mailbox.** Before its first call, each mailbox's Google sign-in is checked against the Gmail profile: a token stored under the wrong address is refused, not used.
4. **Trash and Spam only through their own tools**, which you set to *Needs approval*, never through a label tool.
5. **The *Sent by Claude* label.** Everything the server sends gets it. It can't be taken off, put on other mail, renamed, or copied by a label whose name reads like it (other scripts' lookalike letters, spacing and punctuation count as the same), because it's the second check on the send limit.
6. **What you approve is what goes out:**
   - plain addresses only, at most 10 recipients;
   - every message is read back before it goes, the way a mail server reads it, and refused unless its recipients and subject are exactly the ones in the call (Python decodes `=?...?=` encoded words as it writes a message);
   - no hidden characters in anything sent;
   - a `reply`, and a draft made as a reply, goes only to people already on the message;
   - `from` picks the address it goes out from, and must be one of the mailbox's verified send-as addresses (`check_settings` lists them, and the server reads them afresh on every call); left out, it's the mailbox's own address;
   - `send_draft` must restate the draft's To, Cc, Bcc and subject, and its `from` when that isn't the mailbox's own address (`get_draft` shows it as `sendsFrom`);
   - `forward_message` sends attachments only with `includeAttachments: true`.
7. **Claude changes only its own drafts.** Drafts the server makes carry a header that signs everything the draft would send. Your drafts, or one of its drafts you've since edited in Gmail, can be read but not changed, deleted or sent from here, and the message tools refuse a draft's message id. `adopt_draft` hands one over, so Claude can then work on it like its own: the call must restate the draft's To, Cc, Bcc and subject, so its approval names the draft, and the draft is kept as you left it (editing or sending it from here makes it plain text, dropping its formatting; a draft holding anything more, such as attachments or inline images, is refused by `update_draft` and `send_draft`, so nothing is dropped without your seeing it). Set it to *Needs approval* like the other draft tools.
8. **Hourly limits, shared by every copy of the server** through a DynamoDB table:
   - sends (10 by default);
   - organising that hides mail: trash, spam, archive, label removals, and category labels, which move mail out of Primary (50 by default);
   - every change of any kind (200), so a change always needs the table.
   - No hour ever holds more than the limit: the count is kept in ten-minute slices, and a take adds up the last hour and ten minutes.
   - If the table can't be reached, changes are refused (reading still works).
9. **Audit log.** Every change is logged at WARNING and stored in the table for 90 days: account, tool, ids, recipient domains and outcome (`ok`, `failed`, or `unknown` when Google failed after the change may have happened), never subjects or bodies.

Everything read from Gmail is cleaned of characters that don't show but that Claude would read. Bodies are plain text: the HTML part when there is one (what a mail client shows), turned into text with text an inline style hides left out (`display:none`, `hidden`, zero size or opacity, squeezed to nothing, off the screen); each link shows its real target, and nothing is fetched, so no tracking pixels load. Classes from a style sheet aren't followed, so hiding text that way still reaches Claude: the filter is a second line, and the fence is the first. Bodies come between *UNTRUSTED EMAIL CONTENT* markers that mail can't fake (invisible joiners and look-alike brackets included), and no other string in a result (a subject, a name, a label) can hold a marker.

See [SECURITY.md](SECURITY.md) for the threat model.

## Setting up

You need Python 3.14, an AWS account with a key that can deploy (see step 6), and a Google account for each mailbox.

1. **Make the Google Cloud project** (once, at console.cloud.google.com):
   - Create a project, and turn on the **Gmail API** under *APIs & Services → Library*.
   - Under *Google Auth Platform*, set up the consent screen as **External**, and add the scope `https://www.googleapis.com/auth/gmail.modify` under *Data access*.
   - Under *Clients*, create an OAuth client of type **Web application** with the redirect URI `http://localhost:8765/callback`, and download its JSON (`client_secret_....json`).
   - Under *Audience*, **publish** the app (*In production*): while it's *Testing*, Google expires its refresh tokens after 7 days. Unverified, the consent page warns that Google hasn't verified the app; that's expected for an app only you use.

   One project's client can sign in every mailbox, gmail.com and Workspace alike; each mailbox still gets its own refresh token, revoked on its own. A Workspace whose admin blocks unverified apps needs the client marked trusted under *API controls*. (A project used by one Workspace mailbox alone can be *Internal* instead, with no warning and no expiry.)
2. **Install locally:**
   - `python -m venv .venv`
   - `.venv/Scripts/pip install --no-deps -r requirements.txt` (`.venv/bin/` on Linux and macOS, here and below)
   - `.venv/Scripts/pip install boto3 pytest`, plus `pywin32` on Windows.
3. **List your mailboxes.** Copy `accounts.example.json` to `accounts.json` and list them, with their levels and limits (`accounts.py` describes every field). `accounts.json` stays out of git.
4. **Sign in to Google** for each mailbox: `python google_login.py --account you@example.com --client-json client_secret_....json`. It opens the consent page, checks the token belongs to that address, and writes `data/google-you-example-com.env`.
5. **Set up the connector's own sign-in:** `python setup_signin.py`. It makes a password and an authenticator secret for an app such as Aegis or a password manager, checks a code, and writes `data/signin.env`.
6. **Deploy:** `python deploy.py --apply --signin-file data/signin.env --google-file you@example.com=data/google-you-example-com.env` (one `--google-file` per mailbox). Without `--apply` it only shows what it would do. It uses boto3's usual credentials (`AWS_PROFILE`, or `--profile`) and your configured region, else `us-east-1`. `aws/deploy-policy.json` is the most the deploying key needs, except that making the function's role needs IAM rights once: `deploy.py --apply --only-role`. It makes a Lambda function with a Function URL, a DynamoDB table, SSM SecureStrings for the secrets and a log group, all named `gmail-mcp` (`--name` changes that).
7. **Delete the secrets on disk.** Delete the `data/` files and the client JSON.
8. **Connect claude.ai.** `python deploy.py --url` prints the connector URL. Add it in claude.ai as a custom connector, and sign in with the password and authenticator code. Set every organise, draft and send tool to **Needs approval**.

`python scripts/pin_requirements.py` rewrites `requirements.txt`, with every file's hash, from `requirements.in`.

## Kill switches

| To | Do |
|---|---|
| Turn off one mailbox | set its `level` to `off` in `accounts.json`, then `deploy.py --apply` |
| Turn everything off | `deploy.py --apply --off` (every request gets HTTP 429); `--on` undoes it |
| Sign every client out | `deploy.py --apply --rotate-signing-key`, or a new password with `setup_signin.py` and `--signin-file`. Claude's open drafts then become yours: they can't be changed or sent from here any more |
| Cut off Google | revoke the app at myaccount.google.com/permissions, or in the Workspace admin console; the refresh token stops at once |

## Known limits

- **A signed token can't be revoked on its own.** An access token lasts an hour. A refresh token lasts until the sign-in does (`SIGNIN_DAYS`, 30). Rotating the signing key ends them all.
- **The server can't tell whether you approved a call.** The approval is the client's. The levels, limits and guards above are what hold either way.
- **Who the URL is open to.** Anyone who can reach the URL can attempt a sign-in. The lockout counts per address (an IPv6 /64 counts as one), and 20 failures from anywhere lock everyone out for up to half an hour.
- **Mail in and out is plain text.** The server reads only mail's plain text, and sends only plain text.

## Tests

`.venv/Scripts/python -m pytest -q tests` runs every tool and guard against a fake Gmail API and token endpoint.

## Security

Found a problem? Please report it privately: see [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE). Not affiliated with Google or Anthropic. Use it within the [Google API Services User Data Policy](https://developers.google.com/terms/api-services-user-data-policy) and Gmail's terms.

## Support

This is free and staying that way. If it's useful to you, you can [buy me a coffee](https://buymeacoffee.com/stevenstorie).

Built by [Steven Storie](https://gitlab.com/sstangle73).
