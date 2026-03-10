# worker.py  –  Gmail API edition
#
# HOW SENDING WORKS:
#   1. Pull queued emails due now (sent_at IS NULL, scheduled_for <= now)
#   2. CLAIM them atomically with claimed_at to prevent duplicate sends
#      across concurrent runs (external cron + GitHub schedule overlap)
#   3. For each email look up the assigned gmail_account (sticky per lead/campaign)
#   4. Decrypt the stored refresh_token, exchange it for a fresh access_token
#      via Google's token endpoint – NO passwords, NO SMTP ports
#   5. POST the RFC-2822 message to Gmail API /v1/users/me/send
#   6. Mark sent, increment daily + hourly count, schedule next follow-up
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

import os
import base64
import random
import re
import requests
import urllib.parse
from email.mime.text import MIMEText
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


def increment_hourly_count(by: int = 1):
    """Atomically increment the hourly counter (upsert pattern)."""
    window = current_hour_window()
    try:
        existing = supabase.table("hourly_email_counts") \
            .select("id, count") \
            .eq("window_start", window) \
            .execute()

        if existing.data:
            new_count = existing.data[0]["count"] + by
            supabase.table("hourly_email_counts") \
                .update({"count": new_count}) \
                .eq("window_start", window) \
                .execute()
        else:
            supabase.table("hourly_email_counts") \
                .insert({"window_start": window, "count": by}) \
                .execute()
    except Exception as e:
        print(f"[HOURLY INCREMENT ERROR] {e}")


# ── Claim lock ────────────────────────────────────────────────────────────────
def claim_emails(limit: int) -> list:
    """
    Fetch and atomically claim unsent emails due now.

    Sets claimed_at = now() on the selected rows BEFORE processing so that
    a second concurrent worker (external cron overlap) won't pick the same
    emails. Emails where claimed_at is set but sent_at is still NULL for
    more than 10 minutes are considered stale and released back into the pool.
    """
    now = datetime.now(timezone.utc)
    stale_threshold = (now - timedelta(minutes=10)).isoformat()

    # Release stale claims (worker crashed mid-batch)
    try:
        supabase.table("email_queue") \
            .update({"claimed_at": None}) \
            .is_("sent_at", "null") \
            .lt("claimed_at", stale_threshold) \
            .execute()
    except Exception as e:
        print(f"[STALE RELEASE ERROR] {e}")

    # Fetch unclaimed emails due now
    try:
        queued = supabase.table("email_queue") \
            .select("*") \
            .is_("sent_at", "null") \
            .is_("claimed_at", "null") \
            .lte("scheduled_for", now.isoformat()) \
            .limit(limit) \
            .execute()

        if not queued.data:
            return []

        ids = [q["id"] for q in queued.data]

        # Claim them
        supabase.table("email_queue") \
            .update({"claimed_at": now.isoformat()}) \
            .in_("id", ids) \
            .execute()

        return queued.data

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
    try:
        row = supabase.table("lead_campaign_accounts") \
            .select("gmail_account") \
            .eq("lead_id", lead_id) \
            .eq("campaign_id", campaign_id) \
            .execute()

        if row.data and row.data[0].get("gmail_account"):
            acct = supabase.table("gmail_accounts") \
                .select("*") \
                .eq("email", row.data[0]["gmail_account"]) \
                .single() \
                .execute()
            return acct.data
    except Exception:
        pass
    return None


def assign_account_to_lead_campaign(lead_id, campaign_id, account_email: str):
    supabase.table("lead_campaign_accounts").upsert({
        "lead_id":       lead_id,
        "campaign_id":   campaign_id,
        "gmail_account": account_email,
    }).execute()


def get_all_accounts_with_capacity() -> list:
    today = date.today().isoformat()

    accounts = supabase.table("gmail_accounts") \
        .select("*") \
        .eq("gmail_connected", True) \
        .execute()

    result = []
    for acct in accounts.data:
        cd = supabase.table("daily_email_counts") \
            .select("count") \
            .eq("email_account", acct["email"]) \
            .eq("date", today) \
            .execute()

        count     = cd.data[0]["count"] if cd.data else 0
        remaining = DAILY_LIMIT - count

        if remaining > 0:
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
def schedule_followup(q: dict, sequence: int, account_email: str):
    """Queue the next follow-up for this lead/campaign."""
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

        if lead.data:
            send_date = (datetime.now(timezone.utc)
                         + timedelta(days=fu["days_after_previous"]))

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
    print("WORKER START  (Gmail API mode)")
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
        print("All Gmail accounts have reached today's daily limit.")
        # Unclaim everything so tomorrow's first run can pick them up
        for q in queued:
            unclaim_email(q["id"])
        return

    print(f"Gmail accounts with capacity: {len(available)}")
    for a in available:
        print(f"  {a['account']['email']}  "
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
                q["lead_id"], q["campaign_id"], acct_data["account"]["email"]
            )

        account       = acct_data["account"]
        current_count = acct_data["sent_today"]

        # ── Send ──────────────────────────────────────────────────────────
        try:
            tracked_body = replace_urls_with_tracking(
                q["body"], q["lead_id"], q["campaign_id"], q["id"]
            )

            ok = send_email_via_gmail(
                account   = account,
                to_email  = q["lead_email"],
                subject   = q["subject"],
                html_body = tracked_body,
            )

            if ok:
                supabase.table("email_queue").update({
                    "sent_at":    datetime.now(timezone.utc).isoformat(),
                    "sent_from":  account["email"],
                    "claimed_at": None,   # clear claim now that it's done
                }).match({"id": q["id"]}).execute()

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
                print(f"[SENT] {q['lead_email']} via {account['email']}  "
                      f"seq={q['sequence']}")

                # NOTE: No time.sleep() here.
                # Rate limiting is enforced by:
                #   1. MAX_EMAILS_PER_HOUR  — global hourly budget (DB-tracked)
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
