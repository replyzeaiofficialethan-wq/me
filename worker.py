# worker.py
import os
import smtplib
import base64
import random
import re
from email.mime.text import MIMEText
from datetime import datetime, timedelta, date, timezone
from supabase import create_client
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import urllib.parse

# Initialize Supabase
SUPABASE_URL = os.environ['SUPABASE_URL']
SUPABASE_KEY = os.environ['SUPABASE_SERVICE_ROLE_KEY']
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Encryption key (32 bytes hex)
ENCRYPTION_KEY = bytes.fromhex(os.environ['ENCRYPTION_KEY'])

# ---------------------------------------------------------------------------
# Spintax engine  –  syntax: {{option A|option B|option C}}
# Supports nesting: {{Hello|Hi}} {{world|{{there|friend}}}}
# ---------------------------------------------------------------------------
def process_spintax(text: str) -> str:
    """
    Recursively resolve all {{opt1|opt2|...}} groups in *text*.
    Each group picks ONE option at random. Nested groups are resolved
    inside-out so the chosen branch can itself contain spintax.
    """
    pattern = re.compile(r'\{\{([^{}]+?)\}\}')

    # Keep resolving until no spintax groups remain
    while True:
        match = pattern.search(text)
        if not match:
            break
        options = match.group(1).split('|')
        chosen  = random.choice(options)          # pick one
        text    = text[:match.start()] + chosen + text[match.end():]

    return text


# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------
def aesgcm_decrypt(b64text: str) -> str:
    data  = base64.b64decode(b64text)
    nonce = data[:12]
    ct    = data[12:]
    aesgcm = AESGCM(ENCRYPTION_KEY)
    pt    = aesgcm.decrypt(nonce, ct, None)
    return pt.decode('utf-8')


# ---------------------------------------------------------------------------
# SMTP send
# ---------------------------------------------------------------------------
def send_email_via_smtp(account, to_email, subject, html_body):
    """Send one email via SMTP. Returns True on success."""
    try:
        smtp_password = aesgcm_decrypt(account["encrypted_smtp_password"])

        msg = MIMEText(html_body, "html")
        msg["Subject"] = subject
        msg["From"]    = f"{account['display_name']} <{account['email']}>"
        msg["To"]      = to_email

        smtp = smtplib.SMTP(account["smtp_host"], account["smtp_port"])
        smtp.starttls()
        smtp.login(account["smtp_username"], smtp_password)
        smtp.send_message(msg)
        smtp.quit()
        return True
    except Exception as e:
        print(f"[SMTP ERROR] {to_email}: {e}")
        return False


# ---------------------------------------------------------------------------
# Account management
# ---------------------------------------------------------------------------
def get_account_for_lead_campaign(lead_id, campaign_id):
    """Return the SMTP account previously assigned to this lead/campaign pair."""
    try:
        assignment = supabase.table("lead_campaign_accounts") \
            .select("smtp_account") \
            .eq("lead_id", lead_id) \
            .eq("campaign_id", campaign_id) \
            .execute()

        if assignment.data:
            account = supabase.table("smtp_accounts") \
                .select("*") \
                .eq("email", assignment.data[0]["smtp_account"]) \
                .single() \
                .execute()
            return account.data
    except Exception:
        pass
    return None


def assign_account_to_lead_campaign(lead_id, campaign_id, account_email):
    supabase.table("lead_campaign_accounts").upsert({
        "lead_id":      lead_id,
        "campaign_id":  campaign_id,
        "smtp_account": account_email
    }).execute()


def get_all_accounts_with_capacity():
    """
    Return all SMTP accounts that still have capacity today,
    sorted by most remaining capacity first.
    """
    today    = date.today().isoformat()
    accounts = supabase.table("smtp_accounts").select("*").execute()

    result = []
    for account in accounts.data:
        count_data = supabase.table("daily_email_counts") \
            .select("count") \
            .eq("email_account", account["email"]) \
            .eq("date", today) \
            .execute()

        count     = count_data.data[0]["count"] if count_data.data else 0
        remaining = 100 - count

        if remaining > 0:
            result.append({
                "account":    account,
                "sent_today": count,
                "remaining":  remaining
            })

    result.sort(key=lambda x: x["remaining"], reverse=True)
    return result


def update_daily_count(email_account, new_count):
    today = date.today().isoformat()
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
            .insert({"email_account": email_account, "date": today, "count": new_count}) \
            .execute()


# ---------------------------------------------------------------------------
# Template rendering  (spintax FIRST, then lead-variable substitution)
# ---------------------------------------------------------------------------
def render_email_template(template, lead_data):
    """
    1. Resolve spintax groups  {{opt1|opt2|...}}  – random pick per email.
    2. Replace {variable} placeholders with lead data.
    3. Convert plain newlines to <br> for HTML email rendering.

    Each call gets its own random picks, so every recipient sees a unique
    permutation of the message – unlimited variation with zero duplicate sends.
    """
    # Step 1 – spintax (produces unique body per lead)
    rendered = process_spintax(template)

    # Step 2 – lead variable substitution
    for key, value in lead_data.items():
        if value is None:
            value = ""
        # {key}  (underscore form)
        rendered = rendered.replace("{" + str(key) + "}", str(value))
        # {key with spaces}  (e.g. {ai hooks})
        rendered = rendered.replace("{" + str(key).replace('_', ' ') + "}", str(value))

    # Step 3 – HTML whitespace
    rendered = rendered.replace('\n', '<br>')
    rendered = rendered.replace('  ', '&nbsp;&nbsp;')

    return rendered


# ---------------------------------------------------------------------------
# URL tracking
# ---------------------------------------------------------------------------
def replace_urls_with_tracking(html_content, lead_id, campaign_id, email_queue_id=None):
    app_base_url = os.environ.get('APP_BASE_URL', 'https://replyzeai.com/goods')
    pattern = r'href="(.*?)"'

    def replace_with_tracking(match):
        original_url = match.group(1)
        if '/track/' in original_url or original_url.startswith('mailto:'):
            return match.group(0)
        encoded_url  = urllib.parse.quote(original_url)
        tracking_url = f"{app_base_url}/track/{lead_id}/{campaign_id}?url={encoded_url}"
        if email_queue_id:
            tracking_url += f"&eqid={email_queue_id}"
        return f'href="{tracking_url}"'

    return re.sub(pattern, replace_with_tracking, html_content)


# ---------------------------------------------------------------------------
# Follow-up scheduler
# ---------------------------------------------------------------------------
def schedule_followup(q, sequence, account_email):
    """Queue the next follow-up in the sequence for this lead/campaign."""
    try:
        follow_up = supabase.table("campaign_followups") \
            .select("*") \
            .eq("campaign_id", q["campaign_id"]) \
            .eq("sequence", sequence) \
            .execute()

        if not follow_up.data:
            return  # No more follow-ups

        follow_up = follow_up.data[0]
        lead      = supabase.table("leads").select("*").eq("id", q["lead_id"]).single().execute()

        if lead.data:
            days_delay = follow_up["days_after_previous"]
            send_date  = datetime.now(timezone.utc) + timedelta(days=days_delay)

            # Spintax + variable substitution happens fresh for every follow-up
            rendered_subject = render_email_template(follow_up["subject"], lead.data)
            rendered_body    = render_email_template(follow_up["body"],    lead.data)

            supabase.table("email_queue").insert({
                "campaign_id":   q["campaign_id"],
                "lead_id":       q["lead_id"],
                "lead_email":    q["lead_email"],
                "subject":       rendered_subject,
                "body":          rendered_body,
                "sequence":      sequence,
                "scheduled_for": send_date.isoformat()
            }).execute()

    except Exception as e:
        print(f"[FOLLOWUP ERROR] {e}")


# ---------------------------------------------------------------------------
# Main send loop
# ---------------------------------------------------------------------------
def send_queued():
    print("=" * 60)
    print("WORKER START")
    current_time = datetime.now(timezone.utc)
    print(f"Current UTC: {current_time.isoformat()}")

    queued = supabase.table("email_queue") \
        .select("*") \
        .is_("sent_at", "null") \
        .lte("scheduled_for", current_time.isoformat()) \
        .limit(100) \
        .execute()

    print(f"Emails ready to send: {len(queued.data)}")

    if not queued.data:
        all_queued = supabase.table("email_queue").select("*").execute()
        unsent     = supabase.table("email_queue").select("*").is_("sent_at", "null").execute()
        print(f"Total queue entries : {len(all_queued.data)}")
        print(f"Unsent (future/held): {len(unsent.data)}")
        if unsent.data:
            for e in unsent.data:
                print(f"  ID {e['id']} → scheduled {e['scheduled_for']}")
        return

    available_accounts = get_all_accounts_with_capacity()
    if not available_accounts:
        print("All SMTP accounts have reached today's sending limit.")
        return

    print(f"SMTP accounts with capacity: {len(available_accounts)}")
    for a in available_accounts:
        print(f"  {a['account']['email']}  sent={a['sent_today']}  remaining={a['remaining']}")

    sent_count   = 0
    failed_count = 0
    # Round-robin index (only used for unassigned lead/campaign pairs)
    account_index  = 0
    total_accounts = len(available_accounts)

    for q in queued.data:
        # ---- Pick the SMTP account ----
        assigned_account = get_account_for_lead_campaign(q["lead_id"], q["campaign_id"])

        if assigned_account:
            # Honour sticky assignment; skip if that account is exhausted
            account_found = next(
                (a for a in available_accounts
                 if a["account"]["email"] == assigned_account["email"] and a["remaining"] > 0),
                None
            )
            if not account_found:
                print(f"[SKIP] {q['lead_email']} – assigned account exhausted")
                continue
            account_data = account_found
        else:
            # Round-robin across available accounts
            if total_accounts == 0:
                print("All accounts exhausted mid-batch.")
                break
            account_index  = account_index % total_accounts
            account_data   = available_accounts[account_index]
            assign_account_to_lead_campaign(
                q["lead_id"], q["campaign_id"], account_data["account"]["email"]
            )

        account       = account_data["account"]
        current_count = account_data["sent_today"]

        # ---- Build the email body with tracking links ----
        try:
            tracked_body = replace_urls_with_tracking(
                q["body"],
                q["lead_id"],
                q["campaign_id"],
                q["id"]
            )

            success = send_email_via_smtp(
                account   = account,
                to_email  = q["lead_email"],
                subject   = q["subject"],
                html_body = tracked_body
            )

            if success:
                sent_at  = datetime.now(timezone.utc).isoformat()
                supabase.table("email_queue").update({
                    "sent_at":   sent_at,
                    "sent_from": account["email"]
                }).match({"id": q["id"]}).execute()

                new_count = current_count + 1
                update_daily_count(account["email"], new_count)

                # Update in-memory state
                account_data["sent_today"] = new_count
                account_data["remaining"]  = 100 - new_count

                # Remove exhausted accounts and adjust index
                if new_count >= 100:
                    available_accounts.pop(account_index)
                    total_accounts = len(available_accounts)
                    if total_accounts == 0:
                        print("All accounts reached daily limit – stopping batch.")
                        break
                    if account_index >= total_accounts:
                        account_index = 0
                else:
                    account_index += 1

                # Schedule the next follow-up in the sequence
                schedule_followup(q, q["sequence"] + 1, account["email"])

                sent_count += 1
                print(f"[SENT] {q['lead_email']} via {account['email']}  seq={q['sequence']}")

            else:
                failed_count += 1
                account_index = (account_index + 1) % max(total_accounts, 1)

        except Exception as e:
            print(f"[ERROR] {q['lead_email']}: {e}")
            failed_count += 1
            account_index = (account_index + 1) % max(total_accounts, 1)

    print("=" * 60)
    print(f"DONE  sent={sent_count}  failed={failed_count}")


if __name__ == "__main__":
    send_queued()
