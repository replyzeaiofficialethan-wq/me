# check_replies.py  –  Auto-reply worker for cold outreach inbound replies

import os
import re
import json
import base64
import time
import random
import requests
from datetime import datetime, timezone
from email.mime.text import MIMEText
from supabase import create_client
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
#from notify import notify  # ← ntfy.sh push notifications

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
_groq_cursor: int       = 0

_GROQ_VALID_INTENTS = {
    'YES_WITH_URL', 'YES_NO_URL', 'FORWARDED_LEAD', 'ASKS_PRICE',
    'ASKS_DETAILS', 'PASS_UNSUB', 'NEGATIVE_OBJECTION', 'QUESTION_OTHER', 'UNKNOWN'
}

_GROQ_SYSTEM_PROMPT = """\
You are an intelligent reply analyzer for a real estate AI outreach system called ReplyzeAI.

A real estate agent has replied to an automated cold outreach email. Your job is to:
1. READ and UNDERSTAND exactly what they are saying in their own words
2. Classify their REAL intent — do NOT be fooled by email thread quotes
3. Write a short, human, contextually appropriate reply

INTENT LABELS (pick exactly one):
- YES_WITH_URL       : They want to proceed AND included a listing URL
- YES_NO_URL         : They are interested / want to proceed, no listing URL yet
- FORWARDED_LEAD     : They GENUINELY forwarded a buyer inquiry — the email contains
                       FULL email headers (From:, To:, Subject:, Date:) from a third party
- ASKS_PRICE         : They are asking about pricing / cost
- ASKS_DETAILS       : They want to know how the system works
- PASS_UNSUB         : They are politely declining or asking to be removed
- NEGATIVE_OBJECTION : They are upset, frustrated, correcting wrong information,
                       or angrily telling us to stop — NOT using formal unsubscribe language
- QUESTION_OTHER     : A genuine question not covered above
- UNKNOWN            : Cannot determine intent

CRITICAL RULES:
- "On [date], [person] wrote:" at the bottom is just a quoted email thread — NOT a forwarded lead.
  A real FORWARDED_LEAD contains the full inner email headers (From:, To:, Subject:, Date:) of
  a THIRD PARTY (a buyer/client), not just the agent's own email thread history.
- If the agent is angry, correcting bad info about their listings, or telling us off,
  that is NEGATIVE_OBJECTION — handle it with empathy and a quick apology.
- If they say they have listings under contract, do not want to be contacted, or think
  our info is wrong → NEGATIVE_OBJECTION.
- Only reply with apology/de-escalation for NEGATIVE_OBJECTION; never use a sales pitch.

Respond ONLY with valid JSON (no markdown, no code fences):
{
  "intent": "INTENT_LABEL",
  "reasoning": "1–2 sentence plain-English explanation of what the agent said",
  "reply_html": "Your reply — plain text, 2–3 sentences max, warm and human"
}"""


def _groq_analyze_reply(text: str) -> dict | None:
    """
    Primary intelligence layer.
    Calls Groq to READ the reply, classify intent properly, and generate
    a contextually appropriate response. Returns:
      { intent, reasoning, reply_html }
    Returns None if all keys fail or the model returns unusable output.
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
                    "model": "llama-3.3-70b-versatile",
                    "messages": [
                        {"role": "system", "content": _GROQ_SYSTEM_PROMPT},
                        {"role": "user",   "content": f"Analyze this reply:\n\n{text[:1200]}"},
                    ],
                    "temperature": 0.3,
                    "max_tokens":  400,
                    "response_format": {"type": "json_object"},
                },
                timeout=25,
            )
            if resp.status_code == 200:
                raw = resp.json()["choices"][0]["message"]["content"].strip()
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError:
                    # Strip possible stray fences and retry parse
                    cleaned = re.sub(r'^```[a-z]*\n?|```$', '', raw, flags=re.M).strip()
                    parsed  = json.loads(cleaned)

                intent = parsed.get("intent", "").strip().upper()
                if intent in _GROQ_VALID_INTENTS:
                    return {
                        "intent":     intent,
                        "reasoning":  parsed.get("reasoning",  "")[:500],
                        "reply_html": parsed.get("reply_html", "")[:1000],
                    }
                print(f"[GROQ ANALYZE] unexpected intent: {intent!r}")

            elif resp.status_code == 429:
                print(f"[GROQ] Key {_groq_cursor-1} rate-limited, trying next")
                continue
            else:
                print(f"[GROQ] {resp.status_code}: {resp.text[:120]}")

        except Exception as exc:
            print(f"[GROQ ANALYZE ERROR] {exc}")
            continue

    return None


# Legacy label-only fallback (used only when _groq_analyze_reply fails entirely)
def _groq_classify_llm(text: str) -> str | None:
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
                            "ASKS_DETAILS | PASS_UNSUB | NEGATIVE_OBJECTION | QUESTION_OTHER | UNKNOWN"
                        )},
                        {"role": "user", "content": f"Classify:\n\n{text[:600]}"}
                    ],
                    "temperature": 0.0,
                    "max_tokens":  12,
                }, timeout=15
            )
            if resp.status_code == 200:
                result = resp.json()["choices"][0]["message"]["content"].strip().upper()
                return result if result in _GROQ_VALID_INTENTS else None
            if resp.status_code == 429:
                continue
        except Exception as exc:
            print(f"[GROQ ERROR] {exc}")
            continue
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  URL / LISTING DETECTION
#
#  The key insight: any email signature can contain URLs (company website,
#  Google Maps address link, LinkedIn, Calendly, etc.).  We must NOT fire
#  YES_WITH_URL on those.
#
#  Rule: YES_WITH_URL only fires when the URL is on a known real-estate
#  listing portal AND the path contains a property-level segment
#  (e.g. /homes/, /listing/, /homedetails/, /p/co/…, /realestateandhomes-detail/).
# ══════════════════════════════════════════════════════════════════════════════

# Domains that host actual property listings
_LISTING_DOMAIN_RE = re.compile(
    r'https?://(?:www\.)?'
    r'(?:'
    r'zillow\.com|realtor\.com|redfin\.com|trulia\.com|homes\.com|'
    r'homesnap\.com|kw\.com|coldwellbanker\.com|compass\.com|'
    r'sothebysrealty\.com|century21\.com|berkshirehathawayhs\.com|'
    r'era\.com|movoto\.com|estately\.com|mlslistings\.com|'
    r'matrix\.brightmls\.com|har\.com|mls\.com|homefinder\.com'
    r')'
    r'(?P<path>[^\s"\'<>]*)',   # capture the path for further validation
    re.I
)

# Path must contain one of these property-level segments
_PROPERTY_PATH_RE = re.compile(
    r'/'
    r'(?:homes?|property|properties|listing(?:s)?|'
    r'realestateandhomes-detail|real-estate|'
    r'homedetails|for.?sale|buy|address|detail|'
    r'p/[a-z]{2}/|'           # redfin  /p/co/denver/...
    r'[a-z0-9\-]+-\d{5,}'     # slug ending in MLS/zip number
    r')',
    re.I
)

# URLs that are never listing links (maps, social, tracking, brokerage homepages)
_SKIP_URL_RE = re.compile(
    r'https?://(?:www\.)?'
    r'(?:maps\.google|maps\.apple|goo\.gl/maps|google\.com/maps|'
    r'bing\.com/maps|mapquest\.com|'
    r'linkedin\.com|facebook\.com|instagram\.com|twitter\.com|x\.com|'
    r'youtube\.com|calendly\.com|zoom\.us|'
    r'hubspot|mailchimp|constantcontact|'
    r'[a-z0-9\-]+\.com/unsubscribe|'
    r'track\.|click\.|email\.|mg\.)',
    re.I
)

_RE_HTTP = re.compile(r'https?://[^\s"\'<>]+', re.I)


def _find_listing_url(text: str) -> str | None:
    """
    Return the first URL that is definitely a property listing page.
    Returns None if no such URL exists (including when only signature
    / maps / brokerage homepage URLs are present).
    """
    for m in _RE_HTTP.finditer(text):
        url = m.group(0).rstrip('.,;)>"\'')

        # Hard skip — never a listing
        if _SKIP_URL_RE.match(url):
            continue

        # Must be on a known listing domain
        domain_m = _LISTING_DOMAIN_RE.match(url)
        if not domain_m:
            continue

        # Must have a property-level path segment
        path = domain_m.group('path')
        if _PROPERTY_PATH_RE.search(path):
            return url

    return None


def extract_listing_url(text: str) -> str | None:
    return _find_listing_url(text)


def extract_address_from_url(url: str | None) -> str:
    """
    Pull a human-readable address from a listing URL path.
    NEVER reads query-string parameters — those produce garbage like ?Q=...
    """
    if not url:
        return 'your listing'

    # Strip query string and fragment entirely before parsing
    clean = re.sub(r'[?#].*$', '', url)

    path_m = re.search(
        r'/(?:homes?|property|properties|listing(?:s)?|'
        r'realestateandhomes-detail|real-estate|homedetails|'
        r'address|detail|p/[a-z]{2}/)/'
        r'([a-z0-9][a-z0-9\-]+(?:-[a-z]{2}-\d{5})?)',
        clean, re.I
    )
    if path_m:
        return path_m.group(1).replace('-', ' ').title()

    # Fallback: path segment that has digits (address slug), no percent-encoding
    parts = clean.rstrip('/').split('/')
    for part in reversed(parts):
        if len(part) > 5 and re.search(r'\d', part) and '%' not in part:
            return part.replace('-', ' ').replace('_', ' ').title()

    return clean[:60]


# ── Other regex patterns ──────────────────────────────────────────────────────
_RE_YES = re.compile(
    r"\b(yes|yep|yeah|sure|count me in|i'?m in|let'?s do it|sounds good|"
    r"i'?d like|interested|go ahead|please do|sign me up|i want|"
    r"set it up|let'?s try|i'?ll do it|do it|great idea|love it)\b", re.I
)
_RE_PRICE = re.compile(
    r"\b(price|cost|how much|charge|fee|pricing|rates?|plans?|"
    r"subscription|payment|invoice)\b", re.I
)
_RE_DETAILS = re.compile(
    r"\b(how does|how do|what is|what are|setup|smtp|login|dashboard|"
    r"integrat|works?|explain|technical|details?|api|connect|plug.?in)\b", re.I
)

# PASS — two-tier
_RE_PASS_STRICT = re.compile(r'^\s*pass[.!?\s]*$', re.I)
_RE_PASS_LOOSE  = re.compile(
    r"\b(unsubscribe|opt.?out|remove me|take me off|stop emailing|"
    r"stop contacting|don'?t (email|contact|message) me|"
    r"no longer (interested|want))\b",
    re.I
)

_RE_FORWARD = re.compile(
    r"(------+\s*(forwarded message|original message)|"
    r"begin forwarded message|\bfw[d]?:\b|on .+wrote:\s*\n)",
    re.I | re.MULTILINE
)
_RE_EMAIL_BLOCK = re.compile(
    r"(^from:\s.+\n(to|cc|subject|date):\s)", re.I | re.MULTILINE
)


# ── Intent classifier ─────────────────────────────────────────────────────────

# ── Intent classifier ─────────────────────────────────────────────────────────

def classify_intent(text: str, groq_result: dict | None = None) -> str:
    """
    Uses the pre-fetched Groq analysis when available.
    Falls back to regex rules only if Groq is unavailable.

    Priority when Groq is available:
      — Trust Groq's intent directly (it has read the full message)
      — Override only for YES_WITH_URL when a real listing URL is confirmed

    Priority when Groq is NOT available (regex-only fallback):
      1. YES_WITH_URL   — listing URL on known portal with property path
      2. FORWARDED_LEAD — forwarded email block with full inner headers only
      3. ASKS_PRICE
      4. YES_NO_URL     — positive signal, no listing URL
      5. ASKS_DETAILS
      6. PASS_UNSUB     — strict bare PASS or explicit opt-out language
      7. UNKNOWN
    """
    t = text.strip()

    # ── Groq-first path ───────────────────────────────────────────────────────
    if groq_result and groq_result.get("intent") in _GROQ_VALID_INTENTS:
        groq_intent = groq_result["intent"]
        # If Groq said FORWARDED_LEAD but we also see a real listing URL → upgrade
        if groq_intent == 'FORWARDED_LEAD' and _find_listing_url(t):
            return 'YES_WITH_URL'
        return groq_intent

    # ── Regex-only fallback ───────────────────────────────────────────────────
    if _find_listing_url(t):
        return 'YES_WITH_URL'

    # Only trigger FORWARDED_LEAD when there are FULL inner email headers
    # (From: + To:/Subject:/Date: in block form) — not just "On X wrote:" thread quotes
    if _RE_EMAIL_BLOCK.search(t):
        return 'FORWARDED_LEAD'

    if _RE_PRICE.search(t):
        return 'ASKS_PRICE'

    if _RE_YES.search(t):
        return 'YES_NO_URL'

    if _RE_DETAILS.search(t):
        return 'ASKS_DETAILS'

    if _RE_PASS_STRICT.match(t) or _RE_PASS_LOOSE.search(t):
        return 'PASS_UNSUB'

    llm_result = _groq_classify_llm(t)
    if llm_result:
        return llm_result

    return 'UNKNOWN'


# ── Auto-reply templates ──────────────────────────────────────────────────────

def _tmpl_yes_with_url(address: str, oh_date: str = 'TBD') -> str:
    return (
        f"Perfect — reserving a pilot slot for <strong>{address}</strong>.<br><br>"
        "I'll capture the next 3–5 inbound inquiries and send you confirmed attendees / "
        "booking screenshots before the open house. No setup needed from you.<br><br>"
        f"Quick check: is the open house date/time {oh_date}? "
        "Reply <strong>CONFIRM</strong> if correct or paste the correct date/time."
    )

def _tmpl_yes_no_url() -> str:
    return (
        "Which listing do you want us to take off your plate?<br><br>"
        "Just reply with the address or paste the listing URL and I'll set everything up."
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

def _tmpl_negative_objection() -> str:
    return (
        "I apologize for the confusion — I clearly had incorrect information. "
        "I'll correct my records right away and won't bother you again."
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
            json=payload, timeout=30,
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
                    from_email: str, intent: str, auto_reply_sent: bool,
                    raw_reply: str = '', auto_reply_body: str = '', reasoning: str = ''):
    try:
        supabase.table("processed_replies").insert({
            "gmail_message_id": gmail_msg_id,
            "account_email":    account_email,
            "from_email":       from_email,
            "intent":           intent,
            "auto_reply_sent":  auto_reply_sent,
            "processed_at":     datetime.now(timezone.utc).isoformat(),
            "raw_reply":        raw_reply[:1000]       if raw_reply       else '',
            "auto_reply_body":  auto_reply_body[:1000] if auto_reply_body else '',
            "reasoning":        reasoning[:500]         if reasoning       else '',
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
        lead_r   = supabase.table("leads").select("id").eq("email", agent_email).execute()
        agent_id = lead_r.data[0]['id'] if lead_r.data else None
        r = supabase.table("pilots").insert({
            "agent_email":        agent_email,
            "agent_id":           agent_id,
            "listing_url":        listing_url or '',
            "address":            address,
            "status":             "pending_setup",
            "inbound_count":      0,
            "qualified_count":    0,
            "bookings_confirmed": 0,
            "assigned_account":   from_account_email,
            "created_at":         datetime.now(timezone.utc).isoformat(),
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

def _create_ops_ticket(from_email: str, subject: str, raw_body: str, intent: str):
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

def _store_responded_lead(lead_id: int, email: str, intent: str, raw_reply: str):
    try:
        supabase.table("responded_leads").upsert({
            "email":        email,
            "lead_id":      lead_id,
            "intent":       intent,
            "raw_reply":    raw_reply[:1000],
            "responded_at": datetime.now(timezone.utc).isoformat(),
        }, on_conflict="email").execute()
    except:
        pass


# ── Core message processor ────────────────────────────────────────────────────

def _process_one_message(account: dict, access_token: str, msg: dict):
    headers      = msg['payload']['headers']
    from_raw     = _get_header(headers, 'From')
    subject      = _get_header(headers, 'Subject')
    orig_msg_id  = _get_header(headers, 'Message-ID')
    gmail_msg_id = msg['id']
    thread_id    = msg.get('threadId')

    em_match   = re.search(r'<([^>]+)>', from_raw)
    from_email = (em_match.group(1) if em_match else from_raw).lower().strip()

    if from_email == account['email'].lower():
        return
    if _is_processed(gmail_msg_id):
        return

    lead_r = supabase.table("leads").select("id,email,name,do_not_contact") \
                 .eq("email", from_email).execute()
    if not lead_r.data:
        _mark_processed(gmail_msg_id, account['email'], from_email, 'NOT_A_LEAD', False)
        return

    lead = lead_r.data[0]
    if lead.get('do_not_contact'):
        _mark_processed(gmail_msg_id, account['email'], from_email, 'DO_NOT_CONTACT', False)
        return

    body_text = _extract_plain_text(msg['payload'])
    if not body_text.strip():
        return

    # ── Step 1: Ask Groq to READ the message, classify it, and draft a reply ──
    print(f"  [{from_email}] calling Groq analyze …")
    groq_result = _groq_analyze_reply(body_text)
    if groq_result:
        print(f"  [{from_email}] Groq → intent={groq_result['intent']} reasoning={groq_result['reasoning'][:80]}")
    else:
        print(f"  [{from_email}] Groq unavailable — falling back to regex classifier")

    # ── Step 2: Final intent (Groq-first, regex fallback) ─────────────────────
    intent = classify_intent(body_text, groq_result)
    print(f"  [{from_email}] intent={intent}")

    reasoning = groq_result.get("reasoning", "") if groq_result else ""

    _log_audit('REPLY_RECEIVED', {
        "from":         from_email,
        "subject":      subject,
        "intent":       intent,
        "reasoning":    reasoning,
        "raw_snippet":  body_text[:300],
        "gmail_msg_id": gmail_msg_id,
        "account":      account['email'],
    })

    # ── Step 3: Choose reply ───────────────────────────────────────────────────
    # Prefer Groq's generated reply when available; fall back to static templates.
    groq_reply   = (groq_result or {}).get("reply_html", "").strip()
    reply_html: str | None = None

    if intent == 'YES_WITH_URL':
        url        = extract_listing_url(body_text)
        address    = extract_address_from_url(url)
        reply_html = groq_reply or _tmpl_yes_with_url(address)
        pilot      = _create_pilot(from_email, url, address, account['email'])
        if pilot:
            _log_audit('PILOT_CREATED', {
                "pilot_id": pilot.get('id'),
                "agent":    from_email,
                "url":      url,
                "address":  address,
            })
        _update_lead_status(from_email, 'pilot_pending_setup')

    elif intent == 'YES_NO_URL':
        reply_html = groq_reply or _tmpl_yes_no_url()
        _create_ops_ticket(from_email, subject, body_text, 'YES_AWAITING_LISTING')
        _log_audit('YES_AWAITING_LISTING', {
            "agent":   from_email,
            "account": account['email'],
            "subject": subject,
        })
        _update_lead_status(from_email, 'awaiting_listing')

    elif intent == 'FORWARDED_LEAD':
        url        = extract_listing_url(body_text)
        address    = extract_address_from_url(url)
        reply_html = groq_reply or _tmpl_forwarded_lead(address)
        pilot      = _create_pilot(from_email, url, address, account['email'])
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
        reply_html = groq_reply or _tmpl_asks_price()

    elif intent == 'ASKS_DETAILS':
        reply_html = groq_reply or _tmpl_asks_details()

    elif intent == 'PASS_UNSUB':
        reply_html = groq_reply or _tmpl_pass_unsub()
        _handle_unsub(from_email)
        _log_audit('UNSUBSCRIBED', {"email": from_email})

    elif intent == 'NEGATIVE_OBJECTION':
        # Groq should always have a reply here; fall back to generic apology
        reply_html = groq_reply or _tmpl_negative_objection()
        # Mark do-not-contact — they clearly don't want outreach
        _handle_unsub(from_email)
        _log_audit('NEGATIVE_OBJECTION', {
            "from":      from_email,
            "reasoning": reasoning,
            "account":   account['email'],
        })

    else:
        reply_html = groq_reply or _tmpl_unknown()
        _create_ops_ticket(from_email, subject, body_text, intent)
        _log_audit('OPS_TICKET_CREATED', {"from": from_email, "intent": intent})

   
    # ───────────────────────────────────────────────────────────────────────────

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
                "to":           from_email,
                "intent":       intent,
                "reasoning":    reasoning,
                "auto_reply":   reply_html[:300],
                "account":      account['email'],
            })
            _store_responded_lead(lead['id'], from_email, intent, body_text)
        else:
            print(f"  [FAILED] Auto-reply → {from_email}")
            _log_audit('AUTO_REPLY_FAILED', {
                "to":      from_email,
                "intent":  intent,
                "account": account['email'],
            })
            

    _mark_processed(
        gmail_msg_id, account['email'], from_email,
        intent, auto_reply_sent,
        raw_reply=body_text,
        auto_reply_body=reply_html or '',
        reasoning=reasoning,
    )


# ── Per-account inbox scan ────────────────────────────────────────────────────

def _check_account(account: dict) -> int:
    access_token = get_access_token(account['encrypted_refresh_token'])
    if not access_token:
        print(f"  [SKIP] Cannot obtain access token.")
        return 0
    try:
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
            time.sleep(1)
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
        n      = _check_account(acct)
        total += n
        print(f"  Processed {n} message(s)")

    print("\n" + "=" * 60)
    print(f"DONE  total_processed={total}")

    


if __name__ == "__main__":
    check_all_replies()
