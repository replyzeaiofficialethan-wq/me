# check_replies.py  –  Auto-reply worker for cold outreach inbound replies
#
# WHAT THIS DOES:
#   1. Polls every connected Gmail account for unread inbox messages
#   2. Matches senders against leads in your Supabase leads table
#   3. Classifies intent with regex first, Groq LLM fallback for ambiguous cases
#   4. Sends the correct pre-approved auto-reply template (A–G from your spec)
#   5. Creates pilot records, marks unsubscribes, opens ops tickets, logs everything
#
# MULTIPLE GROQ KEYS:
#   Set GROQ_API_KEY, GROQ_API_KEY_1, GROQ_API_KEY_2 … in your env/secrets.
#   Keys are round-robin rotated; 429s automatically advance to the next key.
#
# NEW ENV VARS NEEDED (add to GitHub Actions secrets + local .env):
#   GROQ_API_KEY        (existing key, still works)
#   GROQ_API_KEY_1      (second key – optional)
#   GROQ_API_KEY_2      (third key – optional)
#   … add as many as you want
#
# GMAIL SCOPE CHANGE:
#   You must re-auth existing Gmail accounts after adding
#   "https://www.googleapis.com/auth/gmail.readonly" to GMAIL_SCOPES in app.py.
#   The new scope lets this worker READ the inbox; the existing scope only sent.
#
# REQUIRED NEW SUPABASE TABLES — see sql_migrations.sql

import os
import re
import base64
import time
import random
import requests
from datetime import datetime, timezone
from email.mime.text import MIMEText
from supabase import create_client
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Supabase ──────────────────────────────────────────────────────────────────
SUPABASE_URL = os.environ['SUPABASE_URL']
SUPABASE_KEY = os.environ['SUPABASE_SERVICE_ROLE_KEY']
supabase     = create_client(SUPABASE_URL, SUPABASE_KEY)

# ── Encryption ────────────────────────────────────────────────────────────────
ENCRYPTION_KEY = bytes.fromhex(os.environ['ENCRYPTION_KEY'])

def aesgcm_decrypt(b64text: str) -> str:
    data  = base64.b64decode(b64text)
    nonce = data[:12]
    ct    = data[12:]
    return AESGCM(ENCRYPTION_KEY).decrypt(nonce, ct, None).decode('utf-8')

# ── Gmail API ─────────────────────────────────────────────────────────────────
GOOGLE_TOKEN_URL     = "https://oauth2.googleapis.com/token"
GOOGLE_CLIENT_ID     = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')

def get_access_token(encrypted_refresh_token: str) -> str | None:
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

# ── Groq multi-key pool ───────────────────────────────────────────────────────
def _load_groq_keys() -> list[str]:
    """Collect all Groq keys from env: GROQ_API_KEY, GROQ_API_KEY_1, GROQ_API_KEY_2 …"""
    keys = []
    base = os.environ.get('GROQ_API_KEY', '').strip()
    if base:
        keys.append(base)
    i = 1
    while True:
        k = os.environ.get(f'GROQ_API_KEY_{i}', '').strip()
        if not k:
            break
        keys.append(k)
        i += 1
    return keys

GROQ_KEYS:    list[str] = _load_groq_keys()
_groq_cursor: int       = 0   # round-robin pointer

def _groq_classify_llm(text: str) -> str | None:
    """
    Fallback LLM intent classifier.  Rotates through all available Groq keys.
    Returns an intent label string or None if all keys fail.
    """
    global _groq_cursor
    if not GROQ_KEYS:
        return None

    for _ in range(len(GROQ_KEYS)):
        key = GROQ_KEYS[_groq_cursor % len(GROQ_KEYS)]
        _groq_cursor += 1

        try:
            resp = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {key}",
                         "Content-Type": "application/json"},
                json={
                    "model": "llama-3.1-8b-instant",
                    "messages": [
                        {"role": "system", "content": (
                            "You classify cold outreach reply intent for a real estate SaaS. "
                            "Respond with EXACTLY one label and nothing else:\n"
                            "YES_WITH_URL | YES_NO_URL | FORWARDED_LEAD | ASKS_PRICE | "
                            "ASKS_DETAILS | PASS_UNSUB | QUESTION_OTHER | UNKNOWN"
                        )},
                        {"role": "user", "content": f"Classify:\n\n{text[:600]}"}
                    ],
                    "temperature": 0.0,
                    "max_tokens": 10,
                }, timeout=15
            )
            if resp.status_code == 200:
                result = resp.json()["choices"][0]["message"]["content"].strip().upper()
                valid  = {
                    'YES_WITH_URL','YES_NO_URL','FORWARDED_LEAD','ASKS_PRICE',
                    'ASKS_DETAILS','PASS_UNSUB','QUESTION_OTHER','UNKNOWN'
                }
                return result if result in valid else None
            if resp.status_code == 429:
                print(f"[GROQ] Key {_groq_cursor-1} rate-limited, trying next")
                continue
            print(f"[GROQ] {resp.status_code}: {resp.text[:120]}")
        except Exception as exc:
            print(f"[GROQ ERROR] {exc}")
            continue

    return None

# ── Regex patterns ────────────────────────────────────────────────────────────
_RE_HTTP    = re.compile(r'https?://\S+', re.I)
_RE_LISTING = re.compile(
    r'(zillow\.com|realtor\.com|redfin\.com|trulia\.com|homes\.com|'
    r'kw\.com|coldwellbanker\.com|compass\.com|sothebys\.com|century21\.com|'
    r'/mls/|mlslistings|homesnap)[^\s]*', re.I
)
_RE_YES     = re.compile(
    r"\b(yes|yep|yeah|sure|count me in|i'?m in|let'?s do it|sounds good|"
    r"i'?d like|interested|go ahead|please do|sign me up|i want|"
    r"set it up|let'?s try|i'?ll do it|do it|great idea|love it)\b", re.I
)
_RE_PRICE   = re.compile(
    r"\b(price|cost|how much|charge|fee|pricing|rates?|plans?|"
    r"subscription|payment|invoice)\b", re.I
)
_RE_DETAILS = re.compile(
    r"\b(how does|how do|what is|what are|setup|smtp|login|dashboard|"
    r"integrat|works?|explain|technical|details?|api|connect|plug.?in)\b", re.I
)
_RE_PASS    = re.compile(
    r"\b(pass|not interested|no thanks|unsubscribe|stop|remove me|"
    r"don'?t (email|contact|message)|opt.?out|take me off|no longer)\b", re.I
)
_RE_FORWARD = re.compile(
    r"(------+\s*(forwarded message|original message)|"
    r"begin forwarded message|"
    r"\bfw[d]?:\b|"
    r"on .+wrote:\s*\n)",
    re.I | re.MULTILINE
)
_RE_EMAIL_BLOCK = re.compile(
    r"(^from:\s.+\n(to|cc|subject|date):\s)", re.I | re.MULTILINE
)


def classify_intent(text: str) -> str:
    """
    Deterministic regex classifier (priority-ordered per spec).
    Falls back to Groq LLM only when regex is inconclusive.
    """
    t = text.strip()

    # Priority 1 – YES_WITH_URL  (URL or listing domain present)
    if _RE_HTTP.search(t) or _RE_LISTING.search(t):
        return 'YES_WITH_URL'

    # Priority 3 – FORWARDED_LEAD  (check before YES to avoid false YES match)
    if _RE_FORWARD.search(t) or _RE_EMAIL_BLOCK.search(t):
        return 'FORWARDED_LEAD'

    # Priority 4 – ASKS_PRICE
    if _RE_PRICE.search(t):
        return 'ASKS_PRICE'

    # Priority 2 – YES_NO_URL
    if _RE_YES.search(t):
        return 'YES_NO_URL'

    # Priority 5 – ASKS_DETAILS
    if _RE_DETAILS.search(t):
        return 'ASKS_DETAILS'

    # Priority 6 – PASS_UNSUB
    if _RE_PASS.search(t):
        return 'PASS_UNSUB'

    # Ambiguous → Groq LLM fallback
    llm_result = _groq_classify_llm(t)
    if llm_result:
        return llm_result

    return 'UNKNOWN'


# ── URL / address helpers ─────────────────────────────────────────────────────
def extract_listing_url(text: str) -> str | None:
    m = _RE_LISTING.search(text)
    if m:
        # Walk backwards in the string to grab the full URL including the scheme
        start = text.rfind('http', 0, m.start())
        if start != -1:
            url_match = _RE_HTTP.search(text, start)
            if url_match:
                return url_match.group(0).rstrip('.,;)')
        return m.group(0).rstrip('.,;)')
    m = _RE_HTTP.search(text)
    return m.group(0).rstrip('.,;)') if m else None


def extract_address_from_url(url: str | None) -> str:
    if not url:
        return 'your listing'
    # Common URL patterns: /address/123-main-st-city-state-zip
    path_match = re.search(
        r'/(?:homes?|property|listing|address|real-estate)/'
        r'([a-z0-9][a-z0-9\-]+(?:-[a-z]{2}-\d{5})?)',
        url, re.I
    )
    if path_match:
        return path_match.group(1).replace('-', ' ').title()
    # Fallback: grab a path segment with a digit (likely an address)
    parts = url.rstrip('/').split('/')
    for part in reversed(parts):
        if len(part) > 5 and re.search(r'\d', part):
            return part.replace('-', ' ').replace('_', ' ').title()
    return url[:60]


# ── Auto-reply templates  (verbatim from spec, section 4 / section 15) ────────
def _tmpl_yes_with_url(address: str, oh_date: str = 'TBD') -> str:
    return (
        f"Perfect — reserving a pilot slot for {address}.<br><br>"
        "I'll capture the next 3–5 inbound inquiries and send you confirmed attendees / "
        "booking screenshots before the open house. No setup needed from you.<br><br>"
        f"Quick check: is the open house date/time {oh_date}? "
        "Reply <strong>CONFIRM</strong> if correct or paste the correct date/time."
    )

def _tmpl_yes_no_url() -> str:
    return (
        "Great — I can do that. Please paste the listing URL (or forward the next buyer "
        "inquiry email for that listing) so I can set this up right away.<br><br>"
        "If you'd rather I pick one of your recent listings, reply <strong>PICK</strong>."
    )

def _tmpl_forwarded_lead(address: str) -> str:
    return (
        f"Got it — I received the forwarded lead for {address}. I'll reply in your voice "
        "and report back with the response &amp; any confirmations. "
        "Expect the first result shortly."
    )

def _tmpl_asks_price() -> str:
    return (
        "Short answer — pilot is free for 3–5 days. I'll send results and plan options "
        "at the end.<br><br>"
        "Reply <strong>PRICE</strong> if you want current plan details now."
    )

def _tmpl_asks_details() -> str:
    return (
        "Good question — no login required for the pilot. I handle setup.<br><br>"
        "Reply <strong>SETUP</strong> to start the pilot, or "
        "<strong>TECH</strong> for a one-paragraph technical breakdown."
    )

def _tmpl_pass_unsub() -> str:
    return (
        "Understood — you're unsubscribed. "
        "If you change your mind any time, reply <strong>START</strong> and I'll re-open a slot."
    )

def _tmpl_unknown() -> str:
    return (
        "Thanks — got your message. "
        "I'll manually review and get back to you within 24 hours."
    )


# ── Gmail helpers ─────────────────────────────────────────────────────────────
def _get_header(headers: list, name: str) -> str:
    for h in headers:
        if h['name'].lower() == name.lower():
            return h['value']
    return ''


def _extract_plain_text(payload: dict) -> str:
    """Recursively find the first text/plain part and decode it."""
    mime = payload.get('mimeType', '')
    if mime == 'text/plain':
        data = payload.get('body', {}).get('data', '')
        if data:
            return base64.urlsafe_b64decode(data + '==').decode('utf-8', errors='replace')
    for part in payload.get('parts', []):
        result = _extract_plain_text(part)
        if result:
            return result
    return ''


def _send_gmail_reply(account: dict, access_token: str,
                      to_email: str, subject: str, html_body: str,
                      thread_id: str | None, orig_message_id: str | None) -> bool:
    """Send a reply through the Gmail API, threading correctly."""
    try:
        reply_subject = subject if subject.lower().startswith('re:') else f"Re: {subject}"
        msg            = MIMEText(html_body, "html", "utf-8")
        msg["To"]      = to_email
        msg["From"]    = f"{account['display_name']} <{account['email']}>"
        msg["Subject"] = reply_subject
        if orig_message_id:
            msg["In-Reply-To"] = orig_message_id
            msg["References"]  = orig_message_id

        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8").rstrip("=")
        payload: dict = {"raw": raw}
        if thread_id:
            payload["threadId"] = thread_id

        resp = requests.post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            headers={"Authorization": f"Bearer {access_token}",
                     "Content-Type": "application/json"},
            json=payload,
            timeout=30,
        )
        return resp.status_code in (200, 201)
    except Exception as exc:
        print(f"[REPLY SEND ERROR] {exc}")
        return False


# ── Supabase helpers ──────────────────────────────────────────────────────────
def _is_processed(gmail_msg_id: str) -> bool:
    try:
        r = supabase.table("processed_replies") \
            .select("id").eq("gmail_message_id", gmail_msg_id).execute()
        return bool(r.data)
    except:
        return False


def _mark_processed(gmail_msg_id: str, account_email: str,
                    from_email: str, intent: str, auto_reply_sent: bool):
    try:
        supabase.table("processed_replies").insert({
            "gmail_message_id": gmail_msg_id,
            "account_email":    account_email,
            "from_email":       from_email,
            "intent":           intent,
            "auto_reply_sent":  auto_reply_sent,
            "processed_at":     datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception as exc:
        print(f"[MARK PROCESSED ERROR] {exc}")


def _log_audit(event_type: str, data: dict):
    try:
        supabase.table("reply_audit_log").insert({
            "event_type": event_type,
            "data":       data,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception as exc:
        print(f"[AUDIT LOG ERROR] {exc}")


def _create_pilot(agent_email: str, listing_url: str | None,
                  address: str, from_account_email: str) -> dict | None:
    try:
        lead_r   = supabase.table("leads").select("id") \
                       .eq("email", agent_email).execute()
        agent_id = lead_r.data[0]['id'] if lead_r.data else None

        r = supabase.table("pilots").insert({
            "agent_email":       agent_email,
            "agent_id":          agent_id,
            "listing_url":       listing_url or '',
            "address":           address,
            "status":            "pending_setup",
            "inbound_count":     0,
            "qualified_count":   0,
            "bookings_confirmed": 0,
            "assigned_account":  from_account_email,
            "created_at":        datetime.now(timezone.utc).isoformat(),
        }).execute()
        return r.data[0] if r.data else None
    except Exception as exc:
        print(f"[CREATE PILOT ERROR] {exc}")
        return None


def _update_lead_status(email: str, status: str):
    try:
        supabase.table("leads") \
            .update({"outreach_status": status}).eq("email", email).execute()
    except:
        pass


def _handle_unsub(email: str):
    try:
        supabase.table("leads") \
            .update({"do_not_contact": True, "outreach_status": "unsubscribed"}) \
            .eq("email", email).execute()
    except:
        pass


def _create_ops_ticket(from_email: str, subject: str,
                       raw_body: str, intent: str):
    try:
        supabase.table("ops_tickets").insert({
            "from_email": from_email,
            "subject":    subject,
            "raw_body":   raw_body[:2000],
            "intent":     intent,
            "status":     "open",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }).execute()
    except Exception as exc:
        print(f"[OPS TICKET ERROR] {exc}")


def _store_responded_lead(lead_id: int, email: str, intent: str,
                          raw_reply: str):
    try:
        supabase.table("responded_leads").upsert({
            "email":         email,
            "lead_id":       lead_id,
            "intent":        intent,
            "raw_reply":     raw_reply[:1000],
            "responded_at":  datetime.now(timezone.utc).isoformat(),
        }, on_conflict="email").execute()
    except:
        pass


# ── Core message processor ────────────────────────────────────────────────────
def _process_one_message(account: dict, access_token: str, msg: dict):
    """Classify and respond to a single Gmail message."""
    headers       = msg['payload']['headers']
    from_raw      = _get_header(headers, 'From')
    subject       = _get_header(headers, 'Subject')
    orig_msg_id   = _get_header(headers, 'Message-ID')
    gmail_msg_id  = msg['id']
    thread_id     = msg.get('threadId')

    # Normalise sender email
    em_match   = re.search(r'<([^>]+)>', from_raw)
    from_email = (em_match.group(1) if em_match else from_raw).lower().strip()

    # Skip our own sent messages showing in inbox
    if from_email == account['email'].lower():
        return

    # Deduplicate
    if _is_processed(gmail_msg_id):
        return

    # Must be a known lead (i.e., someone we contacted)
    lead_r = supabase.table("leads").select("id,email,name,do_not_contact") \
                 .eq("email", from_email).execute()
    if not lead_r.data:
        _mark_processed(gmail_msg_id, account['email'], from_email,
                        'NOT_A_LEAD', False)
        return

    lead = lead_r.data[0]
    if lead.get('do_not_contact'):
        _mark_processed(gmail_msg_id, account['email'], from_email,
                        'DO_NOT_CONTACT', False)
        return

    body_text = _extract_plain_text(msg['payload'])
    if not body_text.strip():
        return

    # ── Classify ─────────────────────────────────────────────────────────────
    intent = classify_intent(body_text)
    print(f"  [{from_email}] intent={intent}")

    _log_audit('REPLY_RECEIVED', {
        "from":         from_email,
        "subject":      subject,
        "intent":       intent,
        "raw_snippet":  body_text[:300],
        "gmail_msg_id": gmail_msg_id,
        "account":      account['email'],
    })

    # ── Build reply & side-effects ────────────────────────────────────────────
    reply_html: str | None = None

    if intent == 'YES_WITH_URL':
        url     = extract_listing_url(body_text)
        address = extract_address_from_url(url)
        reply_html = _tmpl_yes_with_url(address)
        pilot  = _create_pilot(from_email, url, address, account['email'])
        if pilot:
            _log_audit('PILOT_CREATED', {
                "pilot_id": pilot.get('id'),
                "agent":    from_email,
                "url":      url,
                "address":  address,
            })
        _update_lead_status(from_email, 'pilot_pending_setup')

    elif intent == 'YES_NO_URL':
        reply_html = _tmpl_yes_no_url()
        _update_lead_status(from_email, 'awaiting_url')

    elif intent == 'FORWARDED_LEAD':
        url     = extract_listing_url(body_text)
        address = extract_address_from_url(url)
        reply_html = _tmpl_forwarded_lead(address)
        pilot  = _create_pilot(from_email, url, address, account['email'])
        if pilot:
            try:
                supabase.table("pilots").update({
                    "transcripts": [{
                        "type":      "buyer",
                        "raw":       body_text[:2000],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }]
                }).eq("id", pilot['id']).execute()
            except:
                pass
            _log_audit('FORWARDED_LEAD_ATTACHED', {
                "pilot_id": pilot.get('id'),
                "agent":    from_email,
            })
        _update_lead_status(from_email, 'pilot_pending_setup')

    elif intent == 'ASKS_PRICE':
        reply_html = _tmpl_asks_price()

    elif intent == 'ASKS_DETAILS':
        reply_html = _tmpl_asks_details()

    elif intent == 'PASS_UNSUB':
        reply_html = _tmpl_pass_unsub()
        _handle_unsub(from_email)
        _log_audit('UNSUBSCRIBED', {"email": from_email})

    else:  # UNKNOWN / QUESTION_OTHER
        reply_html = _tmpl_unknown()
        _create_ops_ticket(from_email, subject, body_text, intent)
        _log_audit('OPS_TICKET_CREATED', {"from": from_email, "intent": intent})

    # ── Send reply (with spec jitter 90–180 s) ────────────────────────────────
    auto_reply_sent = False
    if reply_html:
        jitter_secs = random.randint(90, 180)
        print(f"  [JITTER] Waiting {jitter_secs}s …")
        time.sleep(jitter_secs)

        ok = _send_gmail_reply(account, access_token,
                               from_email, subject, reply_html,
                               thread_id, orig_msg_id)
        auto_reply_sent = ok

        if ok:
            print(f"  [SENT] Auto-reply → {from_email} ({intent})")
            _log_audit('AUTO_REPLY_SENT', {
                "to":       from_email,
                "intent":   intent,
                "account":  account['email'],
            })
            _store_responded_lead(lead['id'], from_email, intent, body_text)
        else:
            print(f"  [FAILED] Auto-reply → {from_email}")
            _log_audit('AUTO_REPLY_FAILED', {
                "to":      from_email,
                "intent":  intent,
                "account": account['email'],
            })

    _mark_processed(gmail_msg_id, account['email'], from_email,
                    intent, auto_reply_sent)


# ── Per-account inbox scan ─────────────────────────────────────────────────────
def _check_account(account: dict) -> int:
    access_token = get_access_token(account['encrypted_refresh_token'])
    if not access_token:
        print(f"  [SKIP] Cannot obtain access token.")
        return 0

    try:
        # List unread inbox messages (max 50 per run)
        list_resp = requests.get(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages",
            headers={"Authorization": f"Bearer {access_token}"},
            params={"q": "is:unread in:inbox -from:me", "maxResults": 50},
            timeout=20,
        )
        if list_resp.status_code != 200:
            print(f"  [LIST ERROR] {list_resp.status_code} {list_resp.text[:120]}")
            return 0

        refs = list_resp.json().get('messages', [])
        print(f"  Unread inbox messages: {len(refs)}")
        processed = 0

        for ref in refs:
            # Fetch full message
            full_resp = requests.get(
                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{ref['id']}",
                headers={"Authorization": f"Bearer {access_token}"},
                params={"format": "full"},
                timeout=20,
            )
            if full_resp.status_code != 200:
                continue

            try:
                _process_one_message(account, access_token, full_resp.json())
                processed += 1
            except Exception as exc:
                print(f"  [PROCESS ERROR] msg={ref['id']}: {exc}")

            time.sleep(1)   # be gentle on Gmail API rate limits

        return processed

    except Exception as exc:
        print(f"  [ACCOUNT ERROR] {exc}")
        return 0


# ── Entry point ───────────────────────────────────────────────────────────────
def check_all_replies():
    print("=" * 60)
    print("CHECK REPLIES  — Auto-reply worker")
    print(f"UTC: {datetime.now(timezone.utc).isoformat()}")
    print(f"Groq keys loaded: {len(GROQ_KEYS)}"
          + (" (regex-only mode)" if not GROQ_KEYS else ""))

    accounts = supabase.table("gmail_accounts") \
        .select("*").eq("gmail_connected", True).execute()

    print(f"Gmail accounts to check: {len(accounts.data)}")
    total = 0

    for acct in accounts.data:
        print(f"\n── {acct['email']} ──────────────")
        n     = _check_account(acct)
        total += n
        print(f"  Processed {n} message(s)")

    print("\n" + "=" * 60)
    print(f"DONE  total_processed={total}")


if __name__ == "__main__":
    check_all_replies()
