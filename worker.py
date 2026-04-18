# worker.py  –  Gmail API + SMTP edition
#
# HOW SENDING WORKS:
#   1. Pull queued emails due now (sent_at IS NULL, scheduled_for <= now)
#   2. CLAIM them atomically with claimed_at to prevent duplicate sends
#      across concurrent runs (external cron + GitHub schedule overlap)
#   3. For each email look up the assigned account (sticky per lead/campaign).
#      Accounts can be Gmail OAuth (gmail_accounts table) OR plain SMTP
#      (smtp_accounts table). Both rotate together in the same pool.
#   4. Gmail path: decrypt refresh_token → exchange for access_token → Gmail API
#      SMTP path:  decrypt smtp_password → connect via smtplib → STARTTLS/SSL
#   5. Mark sent, increment daily + hourly count, schedule next follow-up
#
# REQUIRED DB CHANGE (run once in Supabase SQL editor):
#   ALTER TABLE lead_campaign_accounts
#     ADD COLUMN IF NOT EXISTS smtp_account TEXT,
#     ADD COLUMN IF NOT EXISTS sender_type  TEXT DEFAULT 'gmail';
#
# THROTTLING (actually works with GitHub Actions cron):
#   - MAX_EMAILS_PER_RUN   : hard cap per worker invocation (default 50)
#   - MAX_EMAILS_PER_HOUR  : global hourly budget across ALL runs (default 100)
#   - GMAIL_DAILY_LIMIT    : per-account daily cap (default 500)
#   - send_delay_seconds / send_jitter_seconds in campaigns table stagger
#     the scheduled_for timestamps so emails drip out across time windows.
#     DO NOT use time.sleep() — it wastes runner minutes and doesn't prevent
#     parallel runs from bypassing it.
#
# REQUIRED ENV VARS:
#   SUPABASE_URL
#   SUPABASE_SERVICE_ROLE_KEY
#   ENCRYPTION_KEY          (same 32-byte hex key used by app.py)
#   GOOGLE_CLIENT_ID        (from Google Cloud Console)
#   GOOGLE_CLIENT_SECRET    (from Google Cloud Console)
#
# OPTIONAL ENV VARS:
#   GMAIL_DAILY_LIMIT       (default: 500)
#   MAX_EMAILS_PER_RUN      (default: 50)   — cap per single worker run
#   MAX_EMAILS_PER_HOUR     (default: 100)  — global cap across all runs in a window
#
# REQUIRED DB CHANGES (run once):
#   -- Claim lock: prevents two workers sending the same email
#   ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;
#
#   -- Hourly counts table (mirrors daily_email_counts but per-hour)
#   CREATE TABLE IF NOT EXISTS hourly_email_counts (
#       id           BIGSERIAL PRIMARY KEY,
#       window_start TIMESTAMPTZ NOT NULL,   -- truncated to the hour
#       count        INT         NOT NULL DEFAULT 0,
#       UNIQUE (window_start)
#   );
#
# ── FIX: REQUIRED SQL FUNCTIONS (run once in Supabase SQL editor) ─────────────
#
#   -- 1. Atomic hourly counter increment (fixes race condition in increment_hourly_count)
#   CREATE OR REPLACE FUNCTION increment_hourly_count(p_window TIMESTAMPTZ, p_by INT)
#   RETURNS void LANGUAGE sql AS $$
#     INSERT INTO hourly_email_counts (window_start, count)
#     VALUES (p_window, p_by)
#     ON CONFLICT (window_start)
#     DO UPDATE SET count = hourly_email_counts.count + p_by;
#   $$;
#
#   -- 2. Atomic claim + stale-release in one query (fixes race window in claim_emails)
#   CREATE OR REPLACE FUNCTION claim_emails(p_limit INT, p_now TIMESTAMPTZ, p_stale TIMESTAMPTZ)
#   RETURNS SETOF email_queue LANGUAGE sql AS $$
#     UPDATE email_queue SET claimed_at = NULL
#     WHERE sent_at IS NULL AND claimed_at IS NOT NULL AND claimed_at < p_stale;
#
#     UPDATE email_queue SET claimed_at = p_now
#     WHERE id IN (
#       SELECT id FROM email_queue
#       WHERE sent_at IS NULL AND claimed_at IS NULL AND scheduled_for <= p_now
#       ORDER BY scheduled_for
#       LIMIT p_limit
#       FOR UPDATE SKIP LOCKED
#     )
#     RETURNING *;
#   $$;

import os
import base64
import random
import re
import smtplib
import requests
import urllib.parse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta, date, timezone
from supabase import create_client
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Supabase ─────────────────────────────────────────────────────────────────
SUPABASE_URL = os.environ['SUPABASE_URL']
SUPABASE_KEY = os.environ['SUPABASE_SERVICE_ROLE_KEY']
supabase     = create_client(SUPABASE_URL, SUPABASE_KEY)

# ── Throttle config ───────────────────────────────────────────────────────────
MAX_EMAILS_PER_RUN  = int(os.environ.get('MAX_EMAILS_PER_RUN',  50))
MAX_EMAILS_PER_HOUR = int(os.environ.get('MAX_EMAILS_PER_HOUR', 100))
DAILY_LIMIT         = int(os.environ.get('GMAIL_DAILY_LIMIT',   500))

# ── Encryption ────────────────────────────────────────────────────────────────
ENCRYPTION_KEY = bytes.fromhex(os.environ['ENCRYPTION_KEY'])

def aesgcm_decrypt(b64text: str) -> str:
    data  = base64.b64decode(b64text)
    nonce = data[:12]
    ct    = data[12:]
    return AESGCM(ENCRYPTION_KEY).decrypt(nonce, ct, None).decode('utf-8')


# ── Spintax ───────────────────────────────────────────────────────────────────
def process_spintax(text: str) -> str:
    """Resolve {{opt1|opt2|opt3}} groups – random pick, supports nesting."""
    pattern = re.compile(r'\{\{([^{}]+?)\}\}')
    while True:
        m = pattern.search(text)
        if not m:
            break
        chosen = random.choice(m.group(1).split('|'))
        text   = text[:m.start()] + chosen + text[m.end():]
    return text


# ── Template rendering ────────────────────────────────────────────────────────
def render_email_template(template: str, lead_data: dict) -> str:
    rendered = process_spintax(template)
    for key, value in lead_data.items():
        if value is None:
            value = ""
        rendered = rendered.replace("{" + str(key) + "}", str(value))
        rendered = rendered.replace("{" + str(key).replace('_', ' ') + "}", str(value))
    rendered = rendered.replace('\n', '<br>')
    rendered = rendered.replace('  ', '&nbsp;&nbsp;')
    return rendered


# ── Gmail API helpers ─────────────────────────────────────────────────────────
GOOGLE_TOKEN_URL     = "https://oauth2.googleapis.com/token"
GOOGLE_GMAIL_SEND    = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
GOOGLE_CLIENT_ID     = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')


def get_gmail_access_token(encrypted_refresh_token: str) -> str | None:
    try:
        refresh_token = aesgcm_decrypt(encrypted_refresh_token)
        resp = requests.post(GOOGLE_TOKEN_URL, data={
            "client_id":     GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "refresh_token": refresh_token,
            "grant_type":    "refresh_token",
        }, timeout=15)

        if resp.status_code == 200:
            return resp.json().get("access_token")

        print(f"[TOKEN ERROR] {resp.status_code}: {resp.text}")
        return None

    except Exception as e:
        print(f"[TOKEN EXCEPTION] {e}")
        return None


def send_email_via_gmail(account: dict, to_email: str,
                          subject: str, html_body: str) -> bool:
    access_token = get_gmail_access_token(account["encrypted_refresh_token"])
    if not access_token:
        print(f"[GMAIL] Cannot get access token for {account['email']}")
        return False

    try:
        msg            = MIMEText(html_body, "html", "utf-8")
        msg["To"]      = to_email
        msg["From"]    = f"{account['display_name']} <{account['email']}>"
        msg["Subject"] = subject

        raw_b64url = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8").rstrip("=")

        resp = requests.post(
            GOOGLE_GMAIL_SEND,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type":  "application/json",
            },
            json={"raw": raw_b64url},
            timeout=30,
        )

        if resp.status_code in (200, 201):
            return True

        print(f"[GMAIL SEND ERROR] {account['email']} -> {to_email}: "
              f"{resp.status_code} {resp.text}")
        return False

    except Exception as e:
        print(f"[GMAIL EXCEPTION] {to_email}: {e}")
        return False


def send_email_via_smtp(account: dict, to_email: str,
                        subject: str, html_body: str) -> bool:
    """Send one email via plain SMTP using stored credentials."""
    try:
        password    = aesgcm_decrypt(account["encrypted_smtp_password"])
        sender_name = account.get("display_name") or account["email"]
        port        = int(account.get("smtp_port") or 587)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"{sender_name} <{account['email']}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        if port == 465:
            server = smtplib.SMTP_SSL(account["smtp_host"], port, timeout=30)
        else:
            server = smtplib.SMTP(account["smtp_host"], port, timeout=30)
            server.ehlo()
            server.starttls()
            server.ehlo()

        server.login(account["smtp_username"], password)
        server.sendmail(account["email"], [to_email], msg.as_string())
        server.quit()
        return True

    except smtplib.SMTPAuthenticationError as e:
        print(f"[SMTP AUTH ERROR] {account['email']}: {e}")
        return False
    except Exception as e:
        print(f"[SMTP EXCEPTION] {account['email']} -> {to_email}: {e}")
        return False


# ── Hourly rate limiter ───────────────────────────────────────────────────────
def current_hour_window() -> str:
    """Return the current UTC hour as an ISO string (e.g. '2025-01-15T14:00:00+00:00')."""
    now = datetime.now(timezone.utc)
    return now.replace(minute=0, second=0, microsecond=0).isoformat()


def get_hourly_sent_count() -> int:
    """How many emails have been sent globally in the current 1-hour window."""
    window = current_hour_window()
    try:
        row = supabase.table("hourly_email_counts") \
            .select("count") \
            .eq("window_start", window) \
            .execute()
        return row.data[0]["count"] if row.data else 0
    except Exception as e:
        print(f"[HOURLY COUNT ERROR] {e}")
        return 0


# FIX: replaced non-atomic read-modify-write with a single atomic SQL upsert via RPC.
# Two concurrent workers previously both read the same count, each added 1, and both
# wrote back the same value — effectively counting only one send instead of two.
# The SQL function uses INSERT ... ON CONFLICT DO UPDATE SET count = count + p_by
# which is evaluated atomically by Postgres, so concurrent calls can never collide.
# Make sure you have created the `increment_hourly_count` SQL function (see header).
def increment_hourly_count(by: int = 1):
    """Atomically increment the hourly counter via a Postgres upsert function."""
    window = current_hour_window()
    try:
        supabase.rpc("increment_hourly_count", {
            "p_window": window,
            "p_by":     by,
        }).execute()
    except Exception as e:
        print(f"[HOURLY INCREMENT ERROR] {e}")


# ── Claim lock ────────────────────────────────────────────────────────────────
# FIX: replaced two-step fetch-then-update with a single atomic SQL function via RPC.
# The old approach had a race window: two concurrent workers could both SELECT the same
# unclaimed rows and then both UPDATE claimed_at on those same IDs — causing duplicate
# sends. The SQL function uses FOR UPDATE SKIP LOCKED, which is Postgres's native
# row-level advisory lock that guarantees each row is claimed by exactly one caller.
# Make sure you have created the `claim_emails` SQL function (see header).
def claim_emails(limit: int) -> list:
    """
    Fetch and atomically claim unsent emails due now.

    Uses a single Postgres function with FOR UPDATE SKIP LOCKED so that
    concurrent workers can never claim the same row. Stale claims (worker
    crashed mid-batch, claimed_at set > 10 min ago with no sent_at) are
    released in the same atomic call.
    """
    now             = datetime.now(timezone.utc)
    stale_threshold = (now - timedelta(minutes=10)).isoformat()

    try:
        result = supabase.rpc("claim_emails", {
            "p_limit": limit,
            "p_now":   now.isoformat(),
            "p_stale": stale_threshold,
        }).execute()
        return result.data if result.data else []
    except Exception as e:
        print(f"[CLAIM ERROR] {e}")
        return []


def unclaim_email(email_id):
    """Release a claim if the send failed (so another run can retry)."""
    try:
        supabase.table("email_queue") \
            .update({"claimed_at": None}) \
            .eq("id", email_id) \
            .execute()
    except Exception:
        pass


# ── Account management ────────────────────────────────────────────────────────
def get_account_for_lead_campaign(lead_id, campaign_id):
    """
    Return the sticky sender account for this lead+campaign, or None.
    Checks both Gmail (sender_type='gmail') and SMTP (sender_type='smtp').
    Falls back to the legacy gmail_account column for older rows.
    """
    try:
        row = supabase.table("lead_campaign_accounts") \
            .select("gmail_account, smtp_account, sender_type") \
            .eq("lead_id", lead_id) \
            .eq("campaign_id", campaign_id) \
            .execute()

        if not row.data:
            return None

        r            = row.data[0]
        sender_type  = r.get("sender_type") or "gmail"
        smtp_email   = r.get("smtp_account")
        gmail_email  = r.get("gmail_account")

        if sender_type == "smtp" and smtp_email:
            acct = supabase.table("smtp_accounts") \
                .select("*") \
                .eq("email", smtp_email) \
                .single() \
                .execute()
            if acct.data:
                acct.data["_type"] = "smtp"
                return acct.data

        if gmail_email:
            acct = supabase.table("gmail_accounts") \
                .select("*") \
                .eq("email", gmail_email) \
                .single() \
                .execute()
            if acct.data:
                acct.data["_type"] = "gmail"
                return acct.data

    except Exception:
        pass
    return None


def assign_account_to_lead_campaign(lead_id, campaign_id, account_email: str,
                                     sender_type: str = "gmail"):
    payload = {
        "lead_id":     lead_id,
        "campaign_id": campaign_id,
        "sender_type": sender_type,
    }
    if sender_type == "smtp":
        payload["smtp_account"]  = account_email
    else:
        payload["gmail_account"] = account_email

    supabase.table("lead_campaign_accounts").upsert(payload).execute()


def get_all_accounts_with_capacity() -> list:
    """
    Return all sending accounts (Gmail + SMTP) that still have daily capacity,
    each tagged with _type='gmail' or _type='smtp'.
    """
    today  = date.today().isoformat()
    result = []

    # ── Gmail accounts ────────────────────────────────────────────────────────
    gmail_rows = supabase.table("gmail_accounts") \
        .select("*") \
        .eq("gmail_connected", True) \
        .execute()

    for acct in (gmail_rows.data or []):
        cd = supabase.table("daily_email_counts") \
            .select("count") \
            .eq("email_account", acct["email"]) \
            .eq("date", today) \
            .execute()
        count     = cd.data[0]["count"] if cd.data else 0
        remaining = DAILY_LIMIT - count
        if remaining > 0:
            acct["_type"] = "gmail"
            result.append({
                "account":     acct,
                "sent_today":  count,
                "remaining":   remaining,
                "daily_limit": DAILY_LIMIT,
            })

    # ── SMTP accounts ─────────────────────────────────────────────────────────
    smtp_rows = supabase.table("smtp_accounts") \
        .select("*") \
        .execute()

    for acct in (smtp_rows.data or []):
        cd = supabase.table("daily_email_counts") \
            .select("count") \
            .eq("email_account", acct["email"]) \
            .eq("date", today) \
            .execute()
        count     = cd.data[0]["count"] if cd.data else 0
        remaining = DAILY_LIMIT - count
        if remaining > 0:
            acct["_type"] = "smtp"
            result.append({
                "account":     acct,
                "sent_today":  count,
                "remaining":   remaining,
                "daily_limit": DAILY_LIMIT,
            })

    result.sort(key=lambda x: x["remaining"], reverse=True)
    return result


def update_daily_count(email_account: str, new_count: int):
    today    = date.today().isoformat()
    existing = supabase.table("daily_email_counts") \
        .select("id") \
        .eq("email_account", email_account) \
        .eq("date", today) \
        .execute()

    if existing.data:
        supabase.table("daily_email_counts") \
            .update({"count": new_count}) \
            .eq("email_account", email_account) \
            .eq("date", today) \
            .execute()
    else:
        supabase.table("daily_email_counts") \
            .insert({"email_account": email_account,
                     "date": today, "count": new_count}) \
            .execute()


# ── URL tracking ───────────────────────────────────────────────────────────────
def replace_urls_with_tracking(html_content, lead_id, campaign_id,
                                email_queue_id=None) -> str:
    app_base_url = os.environ.get('APP_BASE_URL', 'https://replyzeai.com/goods')

    def _replace(match):
        url = match.group(1)
        if '/track/' in url or url.startswith('mailto:'):
            return match.group(0)
        encoded = urllib.parse.quote(url)
        turl    = f"{app_base_url}/track/{lead_id}/{campaign_id}?url={encoded}"
        if email_queue_id:
            turl += f"&eqid={email_queue_id}"
        return f'href="{turl}"'

    return re.sub(r'href="(.*?)"', _replace, html_content)


# ── Follow-up scheduler ────────────────────────────────────────────────────────
# FIX: now reads send_delay_seconds and send_jitter_seconds from the campaign row
# and applies them to the scheduled_for timestamp. Previously the function computed
# send_date as exactly now + days_after_previous with no randomisation, so every
# follow-up fired at the exact same second regardless of campaign jitter settings.
def schedule_followup(q: dict, sequence: int, account_email: str):
    """Queue the next follow-up for this lead/campaign, with delay + jitter applied."""
    try:
        fu = supabase.table("campaign_followups") \
            .select("*") \
            .eq("campaign_id", q["campaign_id"]) \
            .eq("sequence", sequence) \
            .execute()

        if not fu.data:
            return

        fu   = fu.data[0]
        lead = supabase.table("leads") \
            .select("*").eq("id", q["lead_id"]).single().execute()

        if not lead.data:
            return

        # Fetch campaign-level send pacing settings
        camp = supabase.table("campaigns") \
            .select("send_delay_seconds, send_jitter_seconds") \
            .eq("id", q["campaign_id"]) \
            .single() \
            .execute()

        delay  = int((camp.data or {}).get("send_delay_seconds") or 0)
        jitter = int((camp.data or {}).get("send_jitter_seconds") or 0)
        # Apply a random offset within [0, jitter] so each follow-up gets a
        # unique scheduled_for rather than all firing at the same second.
        offset_seconds = delay + (random.randint(0, jitter) if jitter > 0 else 0)

        send_date = (
            datetime.now(timezone.utc)
            + timedelta(days=fu["days_after_previous"])
            + timedelta(seconds=offset_seconds)
        )

        supabase.table("email_queue").insert({
            "campaign_id":   q["campaign_id"],
            "lead_id":       q["lead_id"],
            "lead_email":    q["lead_email"],
            "subject":       render_email_template(fu["subject"], lead.data),
            "body":          render_email_template(fu["body"],    lead.data),
            "sequence":      sequence,
            "scheduled_for": send_date.isoformat(),
        }).execute()

    except Exception as e:
        print(f"[FOLLOWUP ERROR] seq={sequence}: {e}")


# ── Main send loop ─────────────────────────────────────────────────────────────
def send_queued():
    print("=" * 60)
    print("WORKER START  (Gmail API + SMTP mode)")
    now = datetime.now(timezone.utc)
    print(f"UTC: {now.isoformat()}")

    # ── Hourly budget check ───────────────────────────────────────────────────
    hourly_sent = get_hourly_sent_count()
    hourly_remaining = MAX_EMAILS_PER_HOUR - hourly_sent
    print(f"Hourly budget: {hourly_sent} sent / {MAX_EMAILS_PER_HOUR} max "
          f"({hourly_remaining} remaining this hour)")

    if hourly_remaining <= 0:
        print("[THROTTLED] Hourly send limit reached. Exiting.")
        print("=" * 60)
        return

    # ── How many can we send this run? ───────────────────────────────────────
    # Respect both the per-run cap and whatever hourly budget is left
    fetch_limit = min(MAX_EMAILS_PER_RUN, hourly_remaining)
    print(f"Will process up to {fetch_limit} emails this run "
          f"(per-run cap={MAX_EMAILS_PER_RUN}, hourly remaining={hourly_remaining})")

    # ── Claim emails atomically ───────────────────────────────────────────────
    queued = claim_emails(fetch_limit)
    print(f"Emails claimed for this run: {len(queued)}")

    if not queued:
        all_q  = supabase.table("email_queue").select("id").execute()
        unsent = supabase.table("email_queue").select("*").is_("sent_at", "null").execute()
        print(f"Total queue entries : {len(all_q.data)}")
        print(f"Unsent (future/held): {len(unsent.data)}")
        for e in unsent.data[:10]:
            print(f"  ID {e['id']} -> scheduled {e['scheduled_for']}  "
                  f"claimed={e.get('claimed_at', 'null')}")
        return

    # ── Load accounts ─────────────────────────────────────────────────────────
    available    = get_all_accounts_with_capacity()
    if not available:
        print("All sending accounts (Gmail + SMTP) have reached today's daily limit.")
        # Unclaim everything so tomorrow's first run can pick them up
        for q in queued:
            unclaim_email(q["id"])
        return

    print(f"Accounts with capacity: {len(available)}")
    for a in available:
        print(f"  [{a['account']['_type'].upper()}] {a['account']['email']}  "
              f"sent={a['sent_today']}  remaining={a['remaining']}")

    sent_count   = 0
    failed_count = 0
    acct_index   = 0
    total_accnts = len(available)

    for q in queued:

        # ── Pick account ──────────────────────────────────────────────────
        assigned = get_account_for_lead_campaign(q["lead_id"], q["campaign_id"])

        if assigned:
            found = next(
                (a for a in available
                 if a["account"]["email"] == assigned["email"]
                 and a["remaining"] > 0),
                None
            )
            if not found:
                print(f"[SKIP] {q['lead_email']} – assigned account exhausted today")
                unclaim_email(q["id"])  # release so next day's worker can retry
                continue
            acct_data = found
        else:
            if total_accnts == 0:
                print("All accounts exhausted mid-batch.")
                unclaim_email(q["id"])
                break
            acct_index = acct_index % total_accnts
            acct_data  = available[acct_index]
            assign_account_to_lead_campaign(
                q["lead_id"], q["campaign_id"],
                acct_data["account"]["email"],
                sender_type=acct_data["account"].get("_type", "gmail"),
            )

        account       = acct_data["account"]
        current_count = acct_data["sent_today"]

        # ── Send ──────────────────────────────────────────────────────────
        try:
            # Final substitution pass: inject sender name now that we know the account.
            # This resolves {my name} / {my_name} which can't be filled at queue time.
            sender_vars   = {
                "my name": account.get("display_name", ""),
                "my_name": account.get("display_name", ""),
            }
            final_subject = render_email_template(q["subject"], sender_vars)
            final_body    = render_email_template(q["body"],    sender_vars)

            tracked_body = replace_urls_with_tracking(
                final_body, q["lead_id"], q["campaign_id"], q["id"]
            )

            # Dispatch to the right sender based on account type
            account_type = account.get("_type", "gmail")
            if account_type == "smtp":
                ok = send_email_via_smtp(
                    account   = account,
                    to_email  = q["lead_email"],
                    subject   = final_subject,
                    html_body = tracked_body,
                )
            else:
                ok = send_email_via_gmail(
                    account   = account,
                    to_email  = q["lead_email"],
                    subject   = final_subject,
                    html_body = tracked_body,
                )

            if ok:
                supabase.table("email_queue").update({
                    "sent_at":    datetime.now(timezone.utc).isoformat(),
                    "sent_from":  account["email"],
                    "claimed_at": None,   # clear claim now that it's done
                }).eq("id", q["id"]).execute()

                new_count = current_count + 1
                update_daily_count(account["email"], new_count)
                increment_hourly_count(1)

                acct_data["sent_today"] = new_count
                acct_data["remaining"]  = DAILY_LIMIT - new_count

                if new_count >= DAILY_LIMIT:
                    available.pop(acct_index)
                    total_accnts = len(available)
                    if total_accnts == 0:
                        print("All accounts hit daily limit – stopping batch.")
                        break
                    if acct_index >= total_accnts:
                        acct_index = 0
                else:
                    acct_index += 1

                schedule_followup(q, q["sequence"] + 1, account["email"])
                sent_count += 1
                print(f"[SENT] {q['lead_email']} via {account['email']} "
                      f"[{account.get('_type','gmail').upper()}]  "
                      f"seq={q['sequence']}")

                # NOTE: No time.sleep() here.
                # Rate limiting is enforced by:
                #   1. MAX_EMAILS_PER_HOUR  — global hourly budget (DB-tracked, now atomic)
                #   2. MAX_EMAILS_PER_RUN   — per-run cap
                #   3. scheduled_for        — campaign creation staggers timestamps
                #                             so future runs pick up the next batch

            else:
                failed_count += 1
                unclaim_email(q["id"])  # release so next run can retry
                acct_index = (acct_index + 1) % max(total_accnts, 1)

        except Exception as e:
            print(f"[ERROR] {q['lead_email']}: {e}")
            failed_count += 1
            unclaim_email(q["id"])
            acct_index = (acct_index + 1) % max(total_accnts, 1)

    print("=" * 60)
    print(f"DONE  sent={sent_count}  failed={failed_count}")


if __name__ == "__main__":
    send_queued()
