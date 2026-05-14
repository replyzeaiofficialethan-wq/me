import os
import re
import json
import base64
import time
import hashlib
import imaplib
import smtplib
import email as email_lib
import email.utils
import email.header
import requests
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
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

#── UPDATED: Property-focused intents ─────────────────────────────────────────
_GROQ_VALID_INTENTS = {
    'AGENT_HANDLES', 'NOBODY_HANDLES', 'ASSISTANT_HANDLES', 'INTERESTED',
    'ASKS_PRICE', 'ASKS_DETAILS', 'ASKS_IDENTITY', 'ACKNOWLEDGMENT_ONLY',
    'PASS_UNSUB', 'NEGATIVE_OBJECTION', 'NOT_RELEVANT', 'CONFUSED', 'UNKNOWN'
}

#── UPDATED: system prompt rewritten for Instant Auto-Reply service ────────────
_GROQ_SYSTEM_PROMPT = """
You are an intelligent reply analyzer for ReplyzeAI.
A real estate agent has replied to a cold outreach email asking: "When a lead texts about {property_address} during a showing, who replies?"

We provide a service that gives instant auto-replies to property inquiries with full context (bedrooms, bathrooms, HOA fees, etc.), so the agent doesn't have to stop what they are doing. This ensures no lead is missed and the agent looks highly professional.

Your job is to:
1. READ and UNDERSTAND exactly what the agent is saying.
2. Classify their REAL intent.
3. Write a short, human, conversational reply that MIRRORS their tone and energy.

CRITICAL RULES:
- DO NOT MENTION "AI" OR "BOTS". We provide a "service" or "system".
- TONE MIRRORING: If they are brief (e.g. "Me"), be brief. If they are professional, be professional.
- GRADUAL APPROACH: Acknowledge their situation -> Briefly mention the benefit -> Offer a "Live Preview" (NOT a "free trial").
- OFFER: Instead of a "free trial", offer to send a "Live Preview" of how the auto-reply would look for {property_address}.
- Every reply MUST end with: "P.S. If you'd rather not hear from me, just let me know and I'll hop off your inbox."
- Keep it to 2-3 lines max + the P.S.
- Use the sender's name {my_name} at the end of the reply (before the P.S.).

INTENT LABELS:
AGENT_HANDLES      : They say they handle replies themselves (e.g., "Me", "I do", "I handle it").
NOBODY_HANDLES     : They say nobody handles it, they miss leads, or it's a problem (e.g., "Nobody", "I usually miss them", "Good question").
ASSISTANT_HANDLES  : They have an assistant, team, or another service handling it.
INTERESTED         : They are interested or want to know more.
ASKS_PRICE         : They are asking about pricing / cost. (The preview is free).
ASKS_DETAILS       : They want to know how the system works.
ASKS_IDENTITY      : They are asking who you are, what company this is, or if you are a bot.
NOT_RELEVANT       : They say the property is raw land, sold, or not their listing.
CONFUSED           : They don't understand the question or the purpose of the email.
ACKNOWLEDGMENT_ONLY: A brief reply with no clear action — "got it", "ok", signature block only.
PASS_UNSUB         : They are explicitly declining or asking to be removed.
NEGATIVE_OBJECTION : Upset, frustrated, or angrily correcting us.
UNKNOWN            : Cannot determine intent.

REPLY TONE AND OFFER LOGIC:
- If AGENT_HANDLES: Acknowledge it's a lot to stay on top of while out at showings. Our system handles that busy work by giving leads instant property details. Offer to send a live preview for {property_address}.
- If NOBODY_HANDLES: Highlight that missed leads are missed commissions. Our service ensures every lead gets an instant reply with details 24/7. Offer a live preview for {property_address}.
- If NOT_RELEVANT: Acknowledge the specific objection (e.g., "Ah, makes sense if it's raw land—those don't get the same text volume"). Pivot to ask if they have other residential listings where instant info would help.
- If CONFUSED: Briefly explain you saw their listing for {property_address} and were curious about their lead handling during showings. Explain we provide instant context to leads so they don't have to.
- If INTERESTED: Briefly explain the benefit of instant property context and offer the live preview.
- If ASKS_PRICE: Mention the preview/setup for one property is free so they can see the results first.
- If ASKS_IDENTITY: Confidently explain we are Replyze and we help agents automate property inquiries so no lead is missed.

Respond ONLY with valid JSON:
{{
  "intent": "INTENT_LABEL",
  "reasoning": "1–2 sentence plain-English explanation",
  "reply_html": "Your reply — plain text, 2–3 sentences max, mirroring tone\\n\\n— {my_name}\\n\\nP.S. If you'd rather not hear from me, just let me know and I'll hop off your inbox."
}}
"""

def _groq_analyze_reply(text: str, property_address: str = "your listing", my_name: str = "the team") -> dict | None:
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
    
    system_prompt = _GROQ_SYSTEM_PROMPT.format(
        property_address=property_address,
        my_name=my_name
    )

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
                        {"role": "system", "content": system_prompt},
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
                            "You classify cold outreach reply intent for a real estate service.  "
                            "Respond with EXACTLY one label and nothing else:\n"
                            "AGENT_HANDLES | NOBODY_HANDLES | ASSISTANT_HANDLES | INTERESTED | "
                            "ASKS_PRICE | ASKS_DETAILS | ASKS_IDENTITY | ACKNOWLEDGMENT_ONLY |  "
                            "PASS_UNSUB | NEGATIVE_OBJECTION | NOT_RELEVANT | CONFUSED | UNKNOWN "
                        )},
                        {"role": "user",  "content": f"Classify:\n\n{text[:600]}"}
                    ],
                    "temperature": 0.0,
                    "max_tokens":  20,
                }, timeout=15
            )
            if resp.status_code == 200:
                result = resp.json()["choices"][0]["message"]["content"].strip().upper()
                # Clean up potential extra words
                for valid in _GROQ_VALID_INTENTS:
                    if valid in result:
                        return valid
                return None
            if resp.status_code == 429:
                continue
        except Exception as exc:
            print(f"[GROQ ERROR] {exc}")
            continue
    return None



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
    r"\b(how does|how do|what is|what are|setup|works?|explain|technical|details?|api|connect)\b", re.I
)
_RE_IDENTITY = re.compile(
    r"\b(who are you|who is (this|sending this)|what'?s your (last name|"
    r"full name|company|last|name)|who (sent|is) this|what company|"
    r"are you (a real person|a bot|ai|human)|is this (a bot|ai|automated))\b",
    re.I
)
_RE_ACKNOWLEDGMENT = re.compile(
    r"^[\s\W]*(got\sit|ok|okay|k|noted|thanks|thank\syout|thx|ty| "
    r"will\sdo|roger|understood|acknowledged|👍|✓|✔|sounds\sgood| "
    r"appreciate\sit|great\sthanks|good\sto\sknow)[\s\W]*$",
    re.I
)
_RE_AGENT_HANDLES = re.compile(r"\b(i do|me|myself|i handle|i reply)\b", re.I)
_RE_NOBODY_HANDLES = re.compile(r"\b(nobody|no one|don't have|none|miss)\b", re.I)
_RE_ASSISTANT_HANDLES = re.compile(r"\b(assistant|team|secretary|va|office)\b", re.I)
_RE_NOT_RELEVANT = re.compile(r"\b(raw land|land|sold|not my|wrong (listing|property))\b", re.I)
_RE_CONFUSED = re.compile(r"\b(what (do you mean|is this|are you expecting|kind of response)|is this a sales|confused|don't understand)\b", re.I)

#── Intent classifier ─────────────────────────────────────────────────────────
def classify_intent(text: str, groq_result: dict | None = None) -> str:
    """
    Uses the pre-fetched Groq analysis when available.
    Falls back to regex rules only if Groq is unavailable.
    """
    t = text.strip()

    # ── Groq-first path ───────────────────────────────────────────────────────
    if groq_result and groq_result.get("intent") in _GROQ_VALID_INTENTS:
        return groq_result["intent"]

    # ── Regex-only fallback ───────────────────────────────────────────────────
    if _RE_IDENTITY.search(t):
        return 'ASKS_IDENTITY'

    stripped = re.sub(r'(?m)^>.*$', '', t).strip()
    if _RE_ACKNOWLEDGMENT.match(stripped):
        return 'ACKNOWLEDGMENT_ONLY'

    if _RE_AGENT_HANDLES.search(t):
        return 'AGENT_HANDLES'
    
    if _RE_NOBODY_HANDLES.search(t):
        return 'NOBODY_HANDLES'
    
    if _RE_ASSISTANT_HANDLES.search(t):
        return 'ASSISTANT_HANDLES'

    if _RE_NOT_RELEVANT.search(t):
        return 'NOT_RELEVANT'

    if _RE_CONFUSED.search(t):
        return 'CONFUSED'

    if _RE_PRICE.search(t):
        return 'ASKS_PRICE'

    if _RE_YES.search(t):
        return 'INTERESTED'

    if _RE_DETAILS.search(t):
        return 'ASKS_DETAILS'

    if _RE_PASS_STRICT.match(t) or _RE_PASS_LOOSE.search(t):
        return 'PASS_UNSUB'

    llm_result = _groq_classify_llm(t)
    if llm_result:
        return llm_result

    return 'UNKNOWN'

#── Auto-reply templates (Fallbacks) ─────────────────────────────────────────
def _tmpl_ps() -> str:
    return "\n\nP.S. If you'd rather not hear from me, just let me know and I'll hop off your inbox."

def _tmpl_asks_identity(my_name: str) -> str:
    return (
        f"Hey — I'm with Replyze. We provide a service that handles instant auto-replies "
        f"for property inquiries with full context (beds, baths, HOA, etc.) so you never miss a lead while you're busy. "
        f"Want me to send over a live preview of how it would look for one of your listings?\n\n— {my_name}"
        f"{_tmpl_ps()}"
    )

def _tmpl_agent_handles(my_name: str) -> str:
    return (
        f"Got it — it's a lot to stay on top of, especially when you're in the middle of a showing. "
        f"Our system handles that busy work by instantly giving leads the beds/baths/HOA info they're looking for. "
        f"Want me to send you a live preview of how it looks for one of your properties?\n\n— {my_name}"
        f"{_tmpl_ps()}"
    )

def _tmpl_nobody_handles(my_name: str) -> str:
    return (
        f"That makes sense — and missed leads usually mean missed commissions. "
        f"We ensure every inquiry gets an instant response with the exact property details they want (beds, baths, HOA, etc.) 24/7. "
        f"Want me to send a live preview for one of your listings so you can see how it works?\n\n— {my_name}"
        f"{_tmpl_ps()}"
    )

def _tmpl_assistant_handles(my_name: str) -> str:
    return (
        f"Makes sense. Our service can actually supplement your team by providing "
        f"instant, detailed property context (beds/baths/HOA) 24/7 so nothing ever slips through the cracks. "
        f"Want me to send over a live preview for one of your listings to see the difference?\n\n— {my_name}"
        f"{_tmpl_ps()}"
    )

def _tmpl_interested(my_name: str) -> str:
    return (
        f"Happy to explain — we provide a system that sends instant replies to property inquiries "
        f"with all the info they want (bedrooms, bathrooms, HOA fees, etc.) the second they text in. "
        f"It keeps you looking professional while you're busy with other clients. "
        f"Want me to send a live preview for one of your properties this week?\n\n— {my_name}"
        f"{_tmpl_ps()}"
    )

def _tmpl_asks_price(my_name: str) -> str:
    return (
        f"We can set up a live preview for one property completely free so you can see the results first. "
        f"We only talk pricing once you've seen how many more leads stay engaged. "
        f"Want me to send over a preview for one of your listings?\n\n— {my_name}"
        f"{_tmpl_ps()}"
    )

def _tmpl_asks_details(my_name: str) -> str:
    return (
        f"It's zero manual work on your end. We provide instant auto-replies with "
        f"property-specific details (beds, baths, HOA, etc.) so leads get info immediately "
        f"without you having to stop what you're doing. "
        f"Want me to send a live preview for one of your properties to see it in action?\n\n— {my_name}"
        f"{_tmpl_ps()}"
    )

def _tmpl_not_relevant(my_name: str, property_address: str) -> str:
    return (
        f"Ah, that makes sense—{property_address} probably doesn't get the same 'is it still available' heat as a residential listing. "
        f"Do you have any other residential properties where those quick inquiry texts become a distraction? "
        f"I'd love to send you a preview of how we handle those.\n\n— {my_name}"
        f"{_tmpl_ps()}"
    )

def _tmpl_confused(my_name: str, property_address: str) -> str:
    return (
        f"Sorry for the lack of context! I saw your listing for {property_address} and was just curious "
        f"how you handle those quick property inquiries when you're busy with other clients. "
        f"We have a system that provides instant info to leads so you don't have to. "
        f"Want me to send a quick preview of how it works?\n\n— {my_name}"
        f"{_tmpl_ps()}"
    )

def _tmpl_pass_unsub() -> str:
    return (
        "Understood — removing you from our list now. "
        "Best of luck with your listings!"
    )

def _tmpl_negative_objection() -> str:
    return (
        "I apologize for the confusion. I'll correct my records right away and won't reach out again."
    )

def _tmpl_unknown(my_name: str) -> str:
    return (
        f"Thanks — got your message. I'll get back to you with more details shortly.\n\n— {my_name}"
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

#── SMTP reply sender ─────────────────────────────────────────────────────────
def _send_smtp_reply(account: dict, to_email: str, subject: str,
                     html_body: str, orig_message_id: str | None,
                     references: str | None) -> bool:
    """Send an auto-reply via SMTP with proper In-Reply-To/References threading."""
    try:
        smtp_password = aesgcm_decrypt(account['encrypted_smtp_password'])
        reply_subject = subject if subject.lower().startswith('re:') else f"Re: {subject}"

        msg            = MIMEMultipart('alternative')
        msg['Subject'] = reply_subject
        msg['From']    = f"{account.get('display_name', account['email'])} <{account['email']}>"
        msg['To']      = to_email
        if orig_message_id:
            msg['In-Reply-To'] = orig_message_id
            refs = f"{references} {orig_message_id}".strip() if references else orig_message_id
            msg['References']  = refs

        msg.attach(MIMEText(html_body, 'html', 'utf-8'))

        with smtplib.SMTP(account['smtp_host'], int(account.get('smtp_port', 587)),
                          timeout=30) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(account['smtp_username'], smtp_password)
            server.send_message(msg)

        return True
    except Exception as exc:
        print(f"[SMTP REPLY ERROR] {exc}")
        return False


#── IMAP helpers ──────────────────────────────────────────────────────────────
def _imap_connect(account: dict):
    """Return an authenticated, INBOX-selected IMAP4_SSL connection."""
    smtp_password = aesgcm_decrypt(account['encrypted_smtp_password'])
    imap_host     = account.get('imap_host') or account['smtp_host']
    imap_port     = int(account.get('imap_port') or 993)
    mail = imaplib.IMAP4_SSL(imap_host, imap_port)
    mail.login(account['smtp_username'], smtp_password)
    mail.select('INBOX')
    return mail


def _decode_imap_header(raw: str) -> str:
    """Decode RFC-2047 encoded email header value."""
    parts = []
    for chunk, charset in email.header.decode_header(raw or ''):
        if isinstance(chunk, bytes):
            parts.append(chunk.decode(charset or 'utf-8', errors='replace'))
        else:
            parts.append(chunk)
    return ''.join(parts)


def _extract_plain_text_imap(msg) -> str:
    """Walk a parsed email.message.Message and return the first text/plain body."""
    if msg.is_multipart():
        for part in msg.walk():
            if (part.get_content_type() == 'text/plain'
                    and 'attachment' not in str(part.get('Content-Disposition', ''))):
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    return payload.decode(charset, errors='replace')
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or 'utf-8'
            return payload.decode(charset, errors='replace')
    return ''


def _process_one_imap_message(account: dict, raw_bytes: bytes):
    """
    Parse a raw RFC822 message fetched from IMAP and run it through
    the same Groq → intent → auto-reply pipeline used for Gmail messages.
    """
    msg = email_lib.message_from_bytes(raw_bytes)

    from_raw    = _decode_imap_header(msg.get('From', ''))
    subject     = _decode_imap_header(msg.get('Subject', ''))
    orig_msg_id = (msg.get('Message-ID') or '').strip()
    references  = (msg.get('References') or '').strip()

    em_match   = re.search(r'<([^>]+)>', from_raw)
    from_email = (em_match.group(1) if em_match else from_raw).lower().strip()

    # Skip messages we sent
    if from_email == account['email'].lower():
        return

    # Build a stable dedup key — use Message-ID if present, else hash the body preview
    if not orig_msg_id:
        preview    = _extract_plain_text_imap(msg)[:200].encode()
        orig_msg_id = f"<imap-{hashlib.md5(preview).hexdigest()}@local>"

    if _is_processed(orig_msg_id):
        return

    lead_r = supabase.table('leads') \
                 .select('id,email,name,do_not_contact,open_house') \
                 .eq('email', from_email).execute()
    if not lead_r.data:
        _mark_processed(orig_msg_id, account['email'], from_email, 'NOT_A_LEAD', False)
        return

    lead = lead_r.data[0]
    if lead.get('do_not_contact'):
        _mark_processed(orig_msg_id, account['email'], from_email, 'DO_NOT_CONTACT', False)
        return

    body_text = _extract_plain_text_imap(msg)
    if not body_text.strip():
        return

    # ── Step 1: Groq analyze ──────────────────────────────────────────────────
    property_address = lead.get('open_house') or "your listing"
    my_name = account.get('display_name') or "the team"
    print(f"  [{from_email}] calling Groq analyze (IMAP) …")
    groq_result = _groq_analyze_reply(body_text, property_address=property_address, my_name=my_name)
    if groq_result:
        print(f"  [{from_email}] Groq → intent={groq_result['intent']} "
              f"reasoning={groq_result['reasoning'][:80]}")
    else:
        print(f"  [{from_email}] Groq unavailable — falling back to regex classifier")

    # ── Step 2: Final intent ──────────────────────────────────────────────────
    intent     = classify_intent(body_text, groq_result)
    reasoning  = groq_result.get('reasoning', '') if groq_result else ''
    confidence = 0.9 if groq_result else 0.5
    print(f"  [{from_email}] intent={intent}")

    _log_agent_decision(
        from_email=from_email, intent=intent, confidence=confidence,
        reasoning=reasoning, metadata=groq_result or {},
    )

    _log_audit('REPLY_RECEIVED', {
        'from':        from_email,
        'subject':     subject,
        'intent':      intent,
        'reasoning':   reasoning,
        'raw_snippet': body_text[:300],
        'imap_msg_id': orig_msg_id,
        'account':     account['email'],
        'channel':     'smtp_imap',
    })

    # ── Step 3: Choose reply (mirrors Gmail path exactly) ─────────────────────
    groq_reply          = (groq_result or {}).get('reply_html', '').strip()
    reply_html: str | None = None

    if intent == 'AGENT_HANDLES':
        reply_html = groq_reply or _tmpl_agent_handles(my_name)
        _log_audit('AGENT_HANDLES', {
            'from': from_email, 'account': account['email'],
        })
        _update_lead_status(from_email, 'agent_handles')

    elif intent == 'NOBODY_HANDLES':
        reply_html = groq_reply or _tmpl_nobody_handles(my_name)
        _log_audit('NOBODY_HANDLES', {
            'from': from_email, 'account': account['email'],
        })
        _update_lead_status(from_email, 'nobody_handles')

    elif intent == 'ASSISTANT_HANDLES':
        reply_html = groq_reply or _tmpl_assistant_handles(my_name)
        _log_audit('ASSISTANT_HANDLES', {
            'from': from_email, 'account': account['email'],
        })
        _update_lead_status(from_email, 'assistant_handles')

    elif intent == 'INTERESTED':
        reply_html = groq_reply or _tmpl_interested(my_name)
        _log_audit('INTERESTED', {
            'from': from_email, 'account': account['email'],
        })
        _update_lead_status(from_email, 'interested')

    elif intent == 'ASKS_IDENTITY':
        reply_html = groq_reply or _tmpl_asks_identity(my_name)
        _log_audit('ASKS_IDENTITY', {
            'from': from_email, 'reasoning': reasoning, 'account': account['email'],
        })

    elif intent == 'ACKNOWLEDGMENT_ONLY':
        reply_html = None
        _log_audit('ACKNOWLEDGMENT_ONLY', {
            'from': from_email, 'reasoning': reasoning, 'account': account['email'],
        })

    elif intent == 'ASKS_PRICE':
        reply_html = groq_reply or _tmpl_asks_price(my_name)

    elif intent == 'ASKS_DETAILS':
        reply_html = groq_reply or _tmpl_asks_details(my_name)

    elif intent == 'PASS_UNSUB':
        reply_html = groq_reply or _tmpl_pass_unsub()
        _handle_unsub(from_email)
        _log_audit('UNSUBSCRIBED', {'email': from_email})

    elif intent == 'NOT_RELEVANT':
        reply_html = groq_reply or _tmpl_not_relevant(my_name, property_address)
        _log_audit('NOT_RELEVANT', {
            'from': from_email, 'account': account['email'],
        })
        _update_lead_status(from_email, 'not_relevant')

    elif intent == 'CONFUSED':
        reply_html = groq_reply or _tmpl_confused(my_name, property_address)
        _log_audit('CONFUSED', {
            'from': from_email, 'account': account['email'],
        })
        _update_lead_status(from_email, 'confused')

    elif intent == 'NEGATIVE_OBJECTION':
        reply_html = groq_reply or _tmpl_negative_objection()
        _handle_unsub(from_email)
        _log_audit('NEGATIVE_OBJECTION', {
            'from': from_email, 'reasoning': reasoning, 'account': account['email'],
        })

    else:
        reply_html = groq_reply or _tmpl_unknown(my_name)
        create_ops_ticket(from_email, subject, body_text, intent)
        _create_human_review_ticket(from_email, subject, body_text, intent, reasoning)
        _log_audit('OPS_TICKET_CREATED', {'from': from_email, 'intent': intent})

    # ── Step 4: Send reply via SMTP ────────────────────────────────
    _store_responded_lead(lead['id'], from_email, intent, body_text)

    auto_reply_sent = False
    if reply_html:
        ok = _send_smtp_reply(account, from_email, subject, reply_html,
                              orig_msg_id, references)
        auto_reply_sent = ok
        if ok:
            print(f"  [SENT] SMTP auto-reply → {from_email} ({intent})")
            _log_audit('AUTO_REPLY_SENT', {
                'to':         from_email,
                'intent':     intent,
                'reasoning':  reasoning,
                'auto_reply': reply_html[:300],
                'account':    account['email'],
            })
        else:
            print(f"  [FAILED] SMTP auto-reply → {from_email}")
            _log_audit('AUTO_REPLY_FAILED', {
                'to':      from_email,
                'intent':  intent,
                'account': account['email'],
            })

    _mark_processed(
        orig_msg_id, account['email'], from_email,
        intent, auto_reply_sent,
        raw_reply=body_text,
        auto_reply_body=reply_html or '',
        reasoning=reasoning,
    )


def _check_imap_account(account: dict) -> int:
    """
    Connect to the IMAP inbox for one smtp_accounts row, fetch UNSEEN
    messages, and run each through the auto-reply pipeline.
    Returns the number of messages processed.
    """
    if not account.get('imap_host'):
        print(f"  [SKIP] No imap_host configured for {account['email']}")
        return 0

    try:
        mail = _imap_connect(account)
    except Exception as exc:
        print(f"  [IMAP CONNECT ERROR] {account['email']}: {exc}")
        return 0

    try:
        status, data = mail.search(None, 'UNSEEN')
        if status != 'OK':
            print(f"  [IMAP SEARCH ERROR] {status}")
            return 0

        uids = data[0].split()
        print(f"  Unread IMAP messages: {len(uids)}")
        processed = 0

        for uid in uids:
            try:
                status2, msg_data = mail.fetch(uid, '(RFC822)')
                if status2 != 'OK' or not msg_data or not msg_data[0]:
                    continue
                _process_one_imap_message(account, msg_data[0][1])
                processed += 1
            except Exception as exc:
                print(f"  [IMAP PROCESS ERROR] uid={uid}: {exc}")
            time.sleep(1)

        mail.logout()
        return processed

    except Exception as exc:
        print(f"  [IMAP ACCOUNT ERROR] {account['email']}: {exc}")
        try:
            mail.logout()
        except:
            pass
        return 0


#── Supabase helpers ──────────────────────────────────────────────────────────
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


def _update_lead_status(email: str, status: str, responded: bool = True):
    try:
        update_data = {"outreach_status": status}
        if responded:
            update_data["responded"] = True
        supabase.table("leads") \
            .update(update_data).eq("email", email).execute()
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

#── Core message processor ────────────────────────────────────────────────────
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
                 .select("id,email,name,do_not_contact,open_house") \
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
    property_address = lead.get('open_house') or "your listing"
    my_name = account.get('display_name') or "the team"
    print(f"  [{from_email}] calling Groq analyze …")
    groq_result = _groq_analyze_reply(body_text, property_address=property_address, my_name=my_name)
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

    if intent == 'AGENT_HANDLES':
        reply_html = groq_reply or _tmpl_agent_handles(my_name)
        _log_audit('AGENT_HANDLES', {
            "from":    from_email,
            "account": account['email'],
        })
        _update_lead_status(from_email, 'agent_handles')

    elif intent == 'NOBODY_HANDLES':
        reply_html = groq_reply or _tmpl_nobody_handles(my_name)
        _log_audit('NOBODY_HANDLES', {
            "from":    from_email,
            "account": account['email'],
        })
        _update_lead_status(from_email, 'nobody_handles')

    elif intent == 'ASSISTANT_HANDLES':
        reply_html = groq_reply or _tmpl_assistant_handles(my_name)
        _log_audit('ASSISTANT_HANDLES', {
            "from":    from_email,
            "account": account["email"],
        })
        _update_lead_status(from_email, 'assistant_handles')

    elif intent == 'INTERESTED':
        reply_html = groq_reply or _tmpl_interested(my_name)
        _log_audit('INTERESTED', {
            "from":    from_email,
            "account": account["email"],
        })
        _update_lead_status(from_email, 'interested')

    elif intent == 'ASKS_IDENTITY':
        # They want to know who sent this — confirm identity confidently, no apology
        reply_html = groq_reply or _tmpl_asks_identity(my_name)
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
        reply_html = groq_reply or _tmpl_asks_price(my_name)

    elif intent == 'ASKS_DETAILS':
        reply_html = groq_reply or _tmpl_asks_details(my_name)

    elif intent == 'PASS_UNSUB':
        reply_html = groq_reply or _tmpl_pass_unsub()
        _handle_unsub(from_email)
        _log_audit('UNSUBSCRIBED', {"email": from_email})

    elif intent == 'NOT_RELEVANT':
        reply_html = groq_reply or _tmpl_not_relevant(my_name, property_address)
        _log_audit('NOT_RELEVANT', {
            "from":    from_email,
            "account": account['email'],
        })
        _update_lead_status(from_email, 'not_relevant')

    elif intent == 'CONFUSED':
        reply_html = groq_reply or _tmpl_confused(my_name, property_address)
        _log_audit('CONFUSED', {
            "from":    from_email,
            "account": account['email'],
        })
        _update_lead_status(from_email, 'confused')

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
        reply_html = groq_reply or _tmpl_unknown(my_name)
        create_ops_ticket(from_email, subject, body_text, intent)
        _create_human_review_ticket(from_email, subject, body_text, intent, reasoning)
        _log_audit('OPS_TICKET_CREATED', {"from": from_email, "intent": intent})

    # ── Step 4: Send reply ─────────────────────────────────────────────────────
    _store_responded_lead(lead['id'], from_email, intent, body_text)

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

#── Per-account inbox scan ────────────────────────────────────────────────────
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

    total = 0

    # ── 1. Gmail OAuth accounts ───────────────────────────────────────────────
    gmail_accounts = supabase.table("gmail_accounts") \
        .select("*").eq("gmail_connected", True).execute()

    print(f"\nGmail accounts to check: {len(gmail_accounts.data)}")
    for acct in gmail_accounts.data:
        print(f"\n── [Gmail] {acct['email']} ──────────────")
        n      = _check_account(acct)
        total += n
        print(f"  Processed {n} message(s)")

    # ── 2. SMTP / IMAP accounts ───────────────────────────────────────────────
    smtp_rows    = supabase.table("smtp_accounts").select("*").execute()
    imap_accounts = [a for a in smtp_rows.data if a.get("imap_host")]

    print(f"\nSMTP/IMAP accounts to check: {len(imap_accounts)}")
    for acct in imap_accounts:
        print(f"\n── [IMAP] {acct['email']} ──────────────")
        n      = _check_imap_account(acct)
        total += n
        print(f"  Processed {n} message(s)")

    print("\n" + "=" * 60)
    print(f"DONE  total_processed={total}")

if __name__ == "__main__":
    check_all_replies()
