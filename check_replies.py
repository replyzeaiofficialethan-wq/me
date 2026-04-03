import os
import re
import json
import base64
import time
import requests
from datetime import datetime, timezone
from email.mime.text import MIMEText
from supabase import create_client
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
#from notify import notify  # ← ntfy.sh push notifications

#── Supabase ──────────────────────────────────────────────────────────────────
SUPABASE_URL = os.environ['SUPABASE_URL']
SUPABASE_KEY = os.environ['SUPABASE_SERVICE_ROLE_KEY']
supabase     = create_client(SUPABASE_URL, SUPABASE_KEY)

#── Encryption ────────────────────────────────────────────────────────────────
ENCRYPTION_KEY = bytes.fromhex(os.environ['ENCRYPTION_KEY'])

def aesgcm_decrypt(b64text: str) -> str:
    data  = base64.b64decode(b64text)
    nonce = data[:12]
    ct    = data[12:]
    return AESGCM(ENCRYPTION_KEY).decrypt(nonce, ct, None).decode('utf-8')

#── Gmail API ─────────────────────────────────────────────────────────────────
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

#── Groq multi-key pool ───────────────────────────────────────────────────────
def load_groq_keys() -> list[str]:
    keys = []
    base = os.environ.get('GROQ_API_KEY', '').strip()
    if base:
        keys.append(base)
    i = 1
    while True:
        k = os.environ.get(f'GROQ_API_KEY{i}', '').strip()
        if not k:
            break
        keys.append(k)
        i += 1
    return keys

GROQ_KEYS:    list[str] = load_groq_keys()
_groq_cursor: int       = 0

── UPDATED: two new intents added ────────────────────────────────────────────
_GROQ_VALID_INTENTS = {
    'YES_WITH_URL', 'YES_NO_URL', 'CRM_REPLY', 'FORWARDED_LEAD', 'ASKS_PRICE',
    'ASKS_DETAILS', 'PASS_UNSUB', 'NEGATIVE_OBJECTION', 'QUESTION_OTHER',
    'ASKS_IDENTITY', 'ACKNOWLEDGMENT_ONLY', 'UNKNOWN'
}

── UPDATED: system prompt rewritten for CRM re-engagement product ─────────────
_GROQ_SYSTEM_PROMPT = """
You are an intelligent reply analyzer for a real estate AI outreach system called ReplyzeAI.
A real estate agent has replied to a cold outreach email. The email offered to re-engage
their old/cold CRM leads — people who inquired before but went quiet — and book confirmed
showings from that "dead" list. The pitch: we recently re-engaged 40 cold leads for a
$1.5M listing and turned 8 into booked showings. We sync with their CRM in one click,
no manual work required. We want to run a free small batch for them this week.

Your job is to:
READ and UNDERSTAND exactly what they are saying in their own words
Classify their REAL intent — do NOT be fooled by email thread quotes
Write a short, human, contextually appropriate reply

INTENT LABELS (pick exactly one):
YES_WITH_URL       : They want to proceed AND included a listing or property URL
YES_NO_URL         : They are interested / want to proceed, no listing URL yet
CRM_REPLY          : They are answering our question about which CRM they use —
                     look for CRM names (Follow Up Boss, KvCore, Chime, BoomTown,
                     Sierra, LionDesk, HubSpot, Salesforce, Lofty, CINC, etc.) or
                     phrases like "we use X", "I'm on X", "my CRM is X", "don't use one"
FORWARDED_LEAD     : They GENUINELY forwarded a buyer inquiry — the email contains
                     FULL email headers (From:, To:, Subject:, Date:) from a third party
ASKS_PRICE         : They are asking about pricing / cost after the free batch
ASKS_DETAILS       : They want to know how the re-engagement system works
ASKS_IDENTITY      : They are asking WHO sent this — name, company, "who are you",
                     "what's your last name", "who is this", "what company are you with",
                     "are you a real person", "is this a bot". They are NOT upset —
                     they are verifying before engaging. This is a POSITIVE signal.
ACKNOWLEDGMENT_ONLY: A brief reply with no clear action or question — "got it", "ok",
                     "thanks", "noted", short replies that are just a signature block,
                     emoji-only replies, or "sounds good" with no follow-up question.
                     Do NOT confuse with PASS_UNSUB. There is NO opt-out language here.
PASS_UNSUB         : They are EXPLICITLY declining or asking to be removed. Must contain
                     clear opt-out language: "not interested", "remove me", "stop emailing",
                     "unsubscribe", "don't contact me", "no thanks", "please stop".
                     A smiley face, "got it", or brief acknowledgment is NOT this.
NEGATIVE_OBJECTION : Upset, frustrated, or angrily correcting us — wrong info about
                     their closings/listings, thinks we're spam, telling us off.
                     Must have a frustrated or hostile tone. "Who are you?" alone with
                     a neutral tone is NOT this — that is ASKS_IDENTITY.
QUESTION_OTHER     : A genuine question not covered above
UNKNOWN            : Cannot determine intent

CRITICAL RULES:
- "On [date], [person] wrote:" at the bottom is just a quoted email thread — NOT a forwarded
  lead. A real FORWARDED_LEAD contains full inner email headers (From:, To:, Subject:, Date:)
  of a THIRD PARTY (a buyer/client), not just the agent's own thread history.
- If the agent is angry, correcting bad data about their closings, or telling us off →
  NEGATIVE_OBJECTION. Handle with empathy and a brief apology. Never use a sales pitch.
- "Who are you?" / "What's your last name?" with a neutral or curious tone → ASKS_IDENTITY.
  Do not classify curiosity as hostility.
- "Got it", "Thanks", "OK", a smiley face, or a signature-only reply → ACKNOWLEDGMENT_ONLY.
  Do NOT classify as PASS_UNSUB unless they explicitly ask to be removed.

REPLY TONE FOR YES_WITH_URL AND YES_NO_URL (CRITICAL):
Confirm momentum FIRST, then ask for CRM. Keep it to 2–3 lines max. Structure:
1. Confirm action: "Got it — I'll run a small batch on your leads and report back with any qualified buyers ready to tour."
2. Low-friction setup question: "Quick question so I configure it right — which CRM do you use? (Follow Up Boss, KvCore, HubSpot, etc.)"
3. Reassurance: "One-click sync, zero manual work on your end."
Do NOT sound like a form or an onboarding bot. Keep it conversational and forward-moving.

REPLY TONE FOR ASKS_IDENTITY:
They want to know who sent this before engaging. This is a GOOD sign — they're curious,
not hostile. Do NOT apologize. Confidently introduce yourself:
- Your first and last name
- ReplyzeAI
- One line on what we do: re-engage old CRM leads and turn them into booked showings
- One soft re-invite: "Happy to answer any questions — want me to run a small test
  batch on your leads?"
Keep it to 3 lines max. Warm, confident, no sales pressure.

REPLY TONE FOR CRM_REPLY:
Do NOT generate a reply — return an empty string for reply_html.
The admin will handle the next step manually.

REPLY TONE FOR ACKNOWLEDGMENT_ONLY:
Do NOT generate a reply — return an empty string for reply_html.
They acknowledged but showed no intent. Replying risks annoyance.

Respond ONLY with valid JSON (no markdown, no code fences):
{
  "intent": "INTENT_LABEL",
  "reasoning": "1–2 sentence plain-English explanation of what the agent said",
  "reply_html": "Your reply — plain text, 2–3 sentences max, warm and human"
}
"""

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
                         "Content-Type":  "application/json"},
                json={
                    "model":  "llama-3.3-70b-versatile",
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
                    cleaned = re.sub(r'^```[a-z]*\n?|```$', '', raw, flags=re.M).strip()
                    parsed  = json.loads(cleaned)

                intent = parsed.get("intent", "").strip().upper()
                if intent in _GROQ_VALID_INTENTS:
                    return {
                        "intent":     intent,
                        "reasoning":  parsed.get("reasoning", "")[:500],
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
                         "Content-Type":  "application/json"},
                json={
                    "model":  "llama-3.1-8b-instant",
                    "messages": [
                        {"role": "system", "content": (
                            "You classify cold outreach reply intent for a real estate SaaS.  "
                            "Respond with EXACTLY one label and nothing else:\n"
                            "YES_WITH_URL | YES_NO_URL | FORWARDED_LEAD | ASKS_PRICE |  "
                            "ASKS_DETAILS | ASKS_IDENTITY | ACKNOWLEDGMENT_ONLY |  "
                            "PASS_UNSUB | NEGATIVE_OBJECTION | QUESTION_OTHER | UNKNOWN "
                        )},
                        {"role": "user",  "content": f"Classify:\n\n{text[:600]}"}
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

══════════════════════════════════════════════════════════════════════════════
URL / LISTING DETECTION
══════════════════════════════════════════════════════════════════════════════
_LISTING_DOMAIN_RE = re.compile(
    r'https?://(?:www.)?'
    r'(?:'
    r'zillow.com|realtor.com|redfin.com|trulia.com|homes.com|'
    r'homesnap.com|kw.com|coldwellbanker.com|compass.com|'
    r'sothebysrealty.com|century21.com|berkshirehathawayhs.com|'
    r'era.com|movoto.com|estately.com|mlslistings.com|'
    r'matrix.brightmls.com|har.com|mls.com|homefinder.com'
    r')'
    r'(?P<path>[^\s"<>]*)',
    re.I
)
_PROPERTY_PATH_RE = re.compile(
    r'/'
    r'(?:homes?|property|properties|listing(?:s)?|'
    r'realestateandhomes-detail|real-estate|'
    r'homedetails|for.?sale|buy|address|detail|'
    r'p/[a-z]{2}/|'
    r'[a-z0-9-]+-\d{5,}'
    r')',
    re.I
)
_SKIP_URL_RE = re.compile(
    r'https?://(?:www.)?'
    r'(?:maps.google|maps.apple|goo.gl/maps|google.com/maps|'
    r'bing.com/maps|mapquest.com|'
    r'linkedin.com|facebook.com|instagram.com|twitter.com|x.com|'
    r'youtube.com|calendly.com|zoom.us|'
    r'hubspot|mailchimp|constantcontact|'
    r'[a-z0-9-]+.com/unsubscribe|'
    r'track.|click.|email.|mg.)',
    re.I
)
_RE_HTTP = re.compile(r'https?://[^\s"<>]+', re.I)

def _find_listing_url(text: str) -> str | None:
    for m in _RE_HTTP.finditer(text):
        url = m.group(0).rstrip('.,;)>"\'')
        if _SKIP_URL_RE.match(url):
            continue
        domain_m = _LISTING_DOMAIN_RE.match(url)
        if not domain_m:
            continue
        path = domain_m.group('path')
        if _PROPERTY_PATH_RE.search(path):
            return url
    return None

def extract_listing_url(text: str) -> str | None:
    return _find_listing_url(text)

def extract_address_from_url(url: str | None) -> str:
    if not url:
        return 'your listing'
    clean = re.sub(r'[?#].*$', '', url)
    path_m = re.search(
        r'/(?:homes?|property|properties|listing(?:s)?|'
        r'realestateandhomes-detail|real-estate|homedetails|'
        r'address|detail|p/[a-z]{2}/)/'
        r'([a-z0-9][a-z0-9-]+(?:-[a-z]{2}-\d{5})?)',
        clean, re.I
    )
    if path_m:
        return path_m.group(1).replace('-', ' ').title()
    parts = clean.rstrip('/').split('/')
    for part in reversed(parts):
        if len(part) > 5 and re.search(r'\d', part) and '%' not in part:
            return part.replace('-', ' ').replace('_', ' ').title()
    return clean[:60]

#── Regex patterns ─────────────────────────────────────────────────────────────
_RE_PASS_STRICT = re.compile(r'^\s*pass[.!?\s]*$', re.I)
_RE_PASS_LOOSE  = re.compile(
    r"\b(unsubscribe|opt.?out|remove me|take me off|stop emailing| "
    r"stop contacting|don'?t (email|contact|message) me| "
    r"no longer (interested|want))\b",
    re.I
)
_RE_YES = re.compile(
    r"\b(yes|yep|yeah|sure|count me in|i'?m in|let'?s do it|sounds good| "
    r"i'?d like|interested|go ahead|please do|sign me up|i want| "
    r"set it up|let'?s try|i'?ll do it|do it|great idea|love it)\b", re.I
)
_RE_PRICE = re.compile(
    r"\b(price|cost|how much|charge|fee|pricing|rates?|plans?| "
    r"subscription|payment|invoice)\b", re.I
)
_RE_DETAILS = re.compile(
    r"\b(how does|how do|what is|what are|setup|smtp|login|dashboard| "
    r"integrat|works?|explain|technical|details?|api|connect|plug.?in)\b", re.I
)
_RE_FORWARD = re.compile(
    r"(------+\s*(forwarded message|original message)| "
    r"begin forwarded message|\bfw[d]?:\b|on .+wrote:\s*\n)",
    re.I | re.MULTILINE
)
_RE_EMAIL_BLOCK = re.compile(
    r"(^from:\s.+\n(to|cc|subject|date):\s)", re.I | re.MULTILINE
)
_RE_CRM = re.compile(
    r"\b(follow\sup\sboss|kvcore|kv\score|chime|boomtown|boom\stown| "
    r"sierra\sinteractive|liondesk|lion\sdesk|hubspot|salesforce|lofty| "
    r"cinc|ylopo|propertybase|top\sproducer|wise\sagent|real\sgeeks| "
    r"contactually|zoho|monday.?com|pipedrive|no\scrm|don'?t\suse\s(a\s*)?crm| "
    r"(we\s*(use|run|have)|i\suse|i'?m\son|my\scrm\sis)\s+\w+)\b",
    re.I
)

── NEW: identity question regex ──────────────────────────────────────────────
_RE_IDENTITY = re.compile(
    r"\b(who are you|who is (this|katie|sending this)|what'?s your (last name|"
    r"full name|company|last|name)|who (sent|is) this|what company|"
    r"your (affiliation|last name|company)|are you (a real person|a bot|ai|"
    r"human)|is this (a bot|ai|automated)|who am i (talking|speaking) to|"
    r"what org(anization)?|who'?s (this|katie|sending))\b",
    re.I
)

── NEW: acknowledgment-only regex ─────────────────────────────────────────────
_RE_ACKNOWLEDGMENT = re.compile(
    r"^[\s\W]*(got\sit|ok|okay|k|noted|thanks|thank\syout|thx|ty| "
    r"will\sdo|roger|understood|acknowledged|👍|✓|✔|sounds\sgood| "
    r"appreciate\sit|great\sthanks|good\sto\sknow)[\s\W]*$",
    re.I
)

── Intent classifier ─────────────────────────────────────────────────────────
def classify_intent(text: str, groq_result: dict | None = None) -> str:
    """
    Uses the pre-fetched Groq analysis when available.
    Falls back to regex rules only if Groq is unavailable.
    Priority when Groq is available:
      — Trust Groq's intent directly (it has read the full message)
      — Override only for YES_WITH_URL when a real listing URL is confirmed

    Priority when Groq is NOT available (regex-only fallback):
      1. YES_WITH_URL        — listing URL on known portal with property path
      2. FORWARDED_LEAD      — forwarded email block with full inner headers only
      3. ASKS_IDENTITY       — explicit "who are you" type questions
      4. ACKNOWLEDGMENT_ONLY — bare acknowledgment with no action/question
      5. CRM_REPLY           — CRM name or "I use X" phrasing
      6. ASKS_PRICE
      7. YES_NO_URL          — positive signal, no listing URL
      8. ASKS_DETAILS
      9. PASS_UNSUB          — strict bare PASS or explicit opt-out language
      10. UNKNOWN
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
    if _RE_EMAIL_BLOCK.search(t):
        return 'FORWARDED_LEAD'

    if _RE_IDENTITY.search(t):
        return 'ASKS_IDENTITY'

    # Acknowledgment check — must match the whole reply (ignore quoted thread)
    # Strip quoted thread lines before checking
    stripped = re.sub(r'(?m)^>.*$', '', t).strip()
    if _RE_ACKNOWLEDGMENT.match(stripped):
        return 'ACKNOWLEDGMENT_ONLY'

    if _RE_CRM.search(t):
        return 'CRM_REPLY'

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

── Auto-reply templates ──────────────────────────────────────────────────────
def _tmpl_crm_ask() -> str:
    return (
        "Quick question before I get everything set up — "
        "Which CRM do you use to manage your leads? "
        "(Follow Up Boss, KvCore, HubSpot, Salesforce, etc.) "
        "We sync in one click so there's zero manual work on your end."
    )

def _tmpl_asks_identity() -> str:
    return (
        "Hey — great question. I'm with ReplyzeAI. We re-engage old CRM leads "
        "that have gone quiet and turn them into booked showings, syncing directly "
        "with your CRM in one click. "
        "Happy to answer any questions — want me to run a small test batch on your leads?"
    )

def _tmpl_yes_with_url(address: str) -> str:
    return (
        f"Got it — I'll run a small batch around {address} and report back with any "
        f"qualified buyers ready to tour.\n\n"
        f"Quick question so I set it up right — which CRM do you use to manage leads? "
        f"(Follow Up Boss, KvCore, HubSpot, etc.) One-click sync, zero manual work."
    )

def _tmpl_yes_no_url() -> str:
    return (
        "Got it — I'll run a small batch on your leads and report back with any "
        "qualified buyers ready to tour.\n\n"
        "Quick question so I set it up right — which CRM do you use to manage leads? "
        "(Follow Up Boss, KvCore, HubSpot, etc.) One-click sync, zero manual work."
    )

def _tmpl_forwarded_lead(address: str) -> str:
    return (
        f"Got it — I received the forwarded lead for {address}. I'll reach out to them "
        f"and report back with the response and any confirmed bookings. "
        f"Expect the first update shortly."
    )

def _tmpl_asks_price() -> str:
    return (
        "The small batch pilot is completely free — no commitment. "
        "If we don't re-engage any of your cold leads into booked showings, "
        "you owe nothing. We only talk pricing once you've seen results first. "
        "Want me to run the free batch this week?"
    )

def _tmpl_asks_details() -> str:
    return (
        "Good question — zero manual work on your end. "
        "We pull your old/cold leads from your CRM (one-click sync), send them "
        "a short personalised follow-up, qualify who's still interested, and book "
        "confirmed showings directly onto your calendar. "
        "We did this for a $1.5M listing — 40 dead leads, 8 booked showings. "
        "Want me to run a free small batch for yours this week?"
    )

def _tmpl_pass_unsub() -> str:
    return (
        "Understood — removing you from our list now. "
        "You won't hear from us again. Best of luck with your listings!"
    )

def _tmpl_negative_objection() -> str:
    return (
        "I apologize for the confusion — I clearly had incorrect information. "
        "I'll correct my records right away and won't reach out again."
    )

def _tmpl_unknown() -> str:
    return (
        "Thanks — got your message. "
        "I'll manually review and get back to you within 24 hours."
    )

#── Gmail helpers ─────────────────────────────────────────────────────────────
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
                     "Content-Type":  "application/json"},
            json=payload, timeout=30,
        )
        return resp.status_code in (200, 201)
    except Exception as exc:
        print(f"[REPLY SEND ERROR] {exc}")
        return False

── Supabase helpers ──────────────────────────────────────────────────────────
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

def _log_agent_decision(from_email: str, intent: str, confidence: float,
                        reasoning: str, metadata: dict):
    """Log structured decision to agent_decisions table for audit trail."""
    try:
        supabase.table("agent_decisions").insert({
            "email_from": from_email,
            "agent_name":  "ClassifierAgent",
            "decision":   intent,
            "confidence": confidence,
            "reasoning":  reasoning,
            "metadata":   metadata,
        }).execute()
    except Exception as exc:
        print(f"[AGENT DECISION LOG WARNING] {exc}")

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

def create_ops_ticket(from_email: str, subject: str, raw_body: str, intent: str,
                      extra: dict | None = None):
    try:
        row = {
            "from_email": from_email,
            "subject":    subject,
            "raw_body":   raw_body[:2000],
            "intent":     intent,
            "status":     "open",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        if extra:
            import json as _json
            row["raw_body"] = raw_body[:1800] + "\n\n__meta: " + _json.dumps(extra)
        supabase.table("ops_tickets").insert(row).execute()
    except Exception as exc:
        print(f"[OPS TICKET ERROR] {exc}")

def _create_human_review_ticket(from_email: str, subject: str, raw_body: str,
                                intent: str, reasoning: str):
    """Queue low-confidence or UNKNOWN replies for human review."""
    try:
        supabase.table("human_review_queue").insert({
            "email_from":     from_email,
            "thread_data":    {"subject": subject, "body": raw_body[:1000]},
            "agent_decisions": {"intent": intent, "reasoning": reasoning},
            "status":         "pending",
        }).execute()
    except Exception as exc:
        print(f"[HUMAN REVIEW QUEUE WARNING] {exc}")

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

── Core message processor ────────────────────────────────────────────────────
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

    lead_r = supabase.table("leads") \
                 .select("id,email,name,do_not_contact") \
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

    reasoning  = groq_result.get("reasoning", "") if groq_result else ""
    confidence = 0.9 if groq_result else 0.5

    # ── Structured agent decision log ─────────────────────────────────────────
    _log_agent_decision(
        from_email=from_email,
        intent=intent,
        confidence=confidence,
        reasoning=reasoning,
        metadata=groq_result or {},
    )

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
        reply_html  = groq_reply or _tmpl_yes_with_url(address)
        create_ops_ticket(from_email, subject, body_text, 'YES_CRM_PENDING',
                          extra={'listing_url': url or '', 'address': address})
        _log_audit('YES_CRM_PENDING', {
            "from":    from_email,
            "url":     url,
            "address": address,
            "account": account['email'],
        })
        _update_lead_status(from_email, 'crm_pending')

    elif intent == 'YES_NO_URL':
        reply_html = groq_reply or _tmpl_yes_no_url()
        create_ops_ticket(from_email, subject, body_text, 'YES_CRM_PENDING')
        _log_audit('YES_CRM_PENDING', {
            "from":    from_email,
            "account": account['email'],
            "subject": subject,
        })
        _update_lead_status(from_email, 'crm_pending')

    elif intent == 'CRM_REPLY':
        # Admin handles next step manually — no auto-reply sent
        reply_html = None 
        create_ops_ticket(from_email, subject, body_text, 'CRM_REPLY_RECEIVED')
        _log_audit('CRM_REPLY_RECEIVED', {
            "from":      from_email,
            "reasoning": reasoning,
            "snippet":   body_text[:300],
            "account":   account['email'],
        })
        _update_lead_status(from_email, 'crm_known')

    elif intent == 'FORWARDED_LEAD':
        url        = extract_listing_url(body_text)
        address    = extract_address_from_url(url)
        reply_html = groq_reply or _tmpl_forwarded_lead(address)
        pilot      = _create_pilot(from_email, url, address, account['email'])
        if pilot:
            try:
                supabase.table("pilots").update({
                    "transcripts": [{
                        "type":       "buyer",
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

    elif intent == 'ASKS_IDENTITY':
        # They want to know who sent this — confirm identity confidently, no apology
        reply_html = groq_reply or _tmpl_asks_identity()
        _log_audit('ASKS_IDENTITY', {
            "from":      from_email,
            "reasoning": reasoning,
            "account":   account['email'],
        })

    elif intent == 'ACKNOWLEDGMENT_ONLY':
        # Brief ack with no action — do NOT reply, let follow-up sequence handle it
        reply_html = None
        _log_audit('ACKNOWLEDGMENT_ONLY', {
            "from":      from_email,
            "reasoning": reasoning,
            "account":   account['email'],
        })

    elif intent == 'ASKS_PRICE':
        reply_html = groq_reply or _tmpl_asks_price()

    elif intent == 'ASKS_DETAILS':
        reply_html = groq_reply or _tmpl_asks_details()

    elif intent == 'PASS_UNSUB':
        reply_html = groq_reply or _tmpl_pass_unsub()
        _handle_unsub(from_email)
        _log_audit('UNSUBSCRIBED', {"email": from_email})

    elif intent == 'NEGATIVE_OBJECTION':
        reply_html = groq_reply or _tmpl_negative_objection()
        # Mark do-not-contact — they clearly don't want outreach
        _handle_unsub(from_email)
        _log_audit('NEGATIVE_OBJECTION', {
            "from":      from_email,
            "reasoning": reasoning,
            "account":   account['email'],
        })

    else:
        # UNKNOWN or QUESTION_OTHER — queue for human review
        reply_html = groq_reply or _tmpl_unknown()
        create_ops_ticket(from_email, subject, body_text, intent)
        _create_human_review_ticket(from_email, subject, body_text, intent, reasoning)
        _log_audit('OPS_TICKET_CREATED', {"from": from_email, "intent": intent})

    # ── Step 4: Send reply ─────────────────────────────────────────────────────

    auto_reply_sent = False
    if reply_html:
        ok = _send_gmail_reply(account, access_token, 
                               from_email, subject, reply_html,
                               thread_id, orig_msg_id)
        auto_reply_sent = ok

        if ok:
            print(f"  [SENT] Auto-reply → {from_email} ({intent})")
            _log_audit('AUTO_REPLY_SENT', {
                "to":         from_email,
                "intent":     intent,
                "reasoning":  reasoning,
                "auto_reply": reply_html[:300],
                "account":    account['email'],
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

── Per-account inbox scan ────────────────────────────────────────────────────
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

#── Entry point ───────────────────────────────────────────────────────────────
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
