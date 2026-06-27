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
import pytz
import random
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from supabase import create_client
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
try:
    from notify import notify  # ← ntfy.sh push notifications
except ImportError:
    # Fallback no-op if notify module is not available
    def notify(title, message, priority='default', tags=None):
        print(f"[NOTIFY] {title}: {message}")

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

#── Demo Link Builder ─────────────────────────────────────────────────────────
DEMO_LINK_BASE = "https://replyzeai.com/goods/templates/demo"

def _get_email_queue_ids(lead_email: str) -> dict | None:
    """
    Look up the most recent email_queue entry for a lead email.
    Returns {eqid, lead_id, campaign_id} or None if not found.
    """
    try:
        result = supabase.table("email_queue") \
            .select("id, lead_id, campaign_id") \
            .eq("lead_email", lead_email.lower()) \
            .order("created_at", desc=True) \
            .limit(1) \
            .execute()
        if result.data:
            row = result.data[0]
            return {
                "eqid": row["id"],
                "lead_id": row["lead_id"],
                "campaign_id": row["campaign_id"]
            }
    except Exception as e:
        print(f"[EMAIL_QUEUE_LOOKUP ERROR] {e}")
    return None

def _build_demo_link(lead_id: int, campaign_id: int, eqid: int) -> str:
    """Construct the personalized demo link with all required IDs."""
    return f"{DEMO_LINK_BASE}?lead_id={lead_id}&campaign_id={campaign_id}&eqid={eqid}"

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

#── Phrase Randomization Pools ───────────────────────────────────────────────
OPENERS = [
    "Makes sense.",
    "Yeah, fair enough.",
    "Gotcha.",
    "That tracks.",
    "Right.",
    "Exactly."
]

SITUATIONS = [
    "while you're at a showing",
    "during an open house",
    "while driving between showings",
    "when you're tied up with a client",
    "after hours",
]

STYLE_MODES = [
    "brief_casual",
    "observational",
    "slightly_curious",
    "very_short",
]

def get_generation_params():
    """Generates randomized parameters for conversational variability."""
    return {
        "opener": random.choice(OPENERS),
        "situation": random.choice(SITUATIONS),
        "style_mode": random.choice(STYLE_MODES),
    }

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

#── Model configuration for rotation ─────────────────────────────────────────
# Model assignment based on capabilities:
# - gpt-oss-20b: Fast, smaller model for simple tasks
# - llama-4-scout-17b-16e-instruct: Balanced model for complex analysis
# - gpt-oss-120b: Large model for complex reasoning

ANALYSIS_MODELS = [
    "meta-llama/llama-4-scout-17b-16e-instruct",  # Primary: complex intent analysis
    "openai/gpt-oss-20b",                           # Fallback 1: rotation
    "openai/gpt-oss-120b",                          # Fallback 2: rotation
]
_analysis_model_cursor: int = 0

CLASSIFICATION_MODELS = [
    "openai/gpt-oss-20b",                           # Primary: simple classification
    "meta-llama/llama-4-scout-17b-16e-instruct",   # Fallback 1: rotation
    "openai/gpt-oss-120b",                          # Fallback 2: rotation
]
_classification_model_cursor: int = 0

#── Real Estate Agent Intent Classification ────────────────────────────────────
# All intents that receive demo links in the Concierge frame
DEMO_LINK_INTENTS = {
    'INTERESTED', 'PAIN_AWARE', 'ACKNOWLEDGMENT_ONLY',
    'ASKS_PRICE', 'ASKS_DETAILS', 'ASKS_IDENTITY',
    'AGENT_HANDLES', 'NOBODY_HANDLES', 'ASSISTANT_HANDLES',
    'STATUS_TEST', 'AUTHORITY_SIGNAL', 'AGREED_TO_SEE'
}

_GROQ_VALID_INTENTS = {
    'AGENT_HANDLES', 'NOBODY_HANDLES', 'ASSISTANT_HANDLES', 'INTERESTED',
    'ASKS_PRICE', 'ASKS_DETAILS', 'ASKS_IDENTITY', 'ACKNOWLEDGMENT_ONLY',
    'PASS_UNSUB', 'NEGATIVE_OBJECTION', 'NOT_RELEVANT', 'CONFUSED', 'UNKNOWN',
    'STATUS_TEST', 'AUTHORITY_SIGNAL', 'PAIN_AWARE', 'AGREED_TO_SEE'
}

#── System prompt: THE CONCIERGE FRAME ───────────────────────────────────────
_GROQ_SYSTEM_PROMPT = """
You are a CONCIERGE, not a salesperson or auditor.

Your job is to deliver value immediately. When a real estate agent responds positively or neutrally to our outreach, you send them a personalized demo link — no questions asked, no diagnosis, no "belief questions."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DIRECT-TO-VALUE RULE (CORE PRINCIPLE)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

When the lead shows ANY positive or neutral signal, your ONLY job is to:
1. Acknowledge their response briefly
2. Deliver the demo link: {{DEMO_LINK}}

No discovery questions. No "Do you think speed matters?" No belief profiling.
The demo link is the focal point — make it stand out.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BREVITY MIRRORING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Match the lead's length and energy:
- They sent 1 word → 1-2 words + demo link
- They sent 1 sentence → 1-2 sentences + demo link
- They sent a paragraph → brief acknowledgment + demo link

The demo link {{DEMO_LINK}} MUST appear in the reply for positive/neutral intents.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
INTENT CLASSIFICATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Classify into ONE of these labels:

INTERESTED         : Explicitly interested, wants to know more, asks questions.
PAIN_AWARE         : Explicitly admits to losing leads, response lag, or missed deals.
ACKNOWLEDGMENT_ONLY: Brief non-action reply ("got it", "ok", "thanks").
ASKS_PRICE         : Asking about pricing/cost.
ASKS_DETAILS       : Asking how the system works.
ASKS_IDENTITY      : Asking who you are.
AGENT_HANDLES      : They handle replies themselves (e.g., "Me", "I do").
NOBODY_HANDLES     : Nobody handles it, they miss leads, it's a problem.
ASSISTANT_HANDLES  : They have assistant/team/coordinator handling inbound.
NOT_RELEVANT       : Not a real estate agent.
CONFUSED           : Doesn't understand the email's purpose.
PASS_UNSUB         : Explicitly declining/removal request.
NEGATIVE_OBJECTION : Upset, frustrated, or angry.
UNKNOWN            : Cannot determine intent.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REPLY RULES BY INTENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

INTERESTED, PAIN_AWARE, ACKNOWLEDGMENT_ONLY:
→ MUST include {{DEMO_LINK}} in reply_html
→ Keep it brief and direct
→ Example: "Great — here's a quick demo: {{DEMO_LINK}}"
→ Example: "Totally get it. See for yourself: {{DEMO_LINK}}"

ASKS_PRICE, ASKS_DETAILS:
→ Include {{DEMO_LINK}} — the demo answers these questions
→ Example: "Here's how it works: {{DEMO_LINK}}"

ASKS_IDENTITY:
→ Introduce yourself briefly, then {{DEMO_LINK}}
→ Example: "I'm {my_name}. Quick overview: {{DEMO_LINK}}"

AGENT_HANDLES, NOBODY_HANDLES, ASSISTANT_HANDLES:
→ Acknowledge their situation, then {{DEMO_LINK}}
→ These are positive signals — they're engaging

PASS_UNSUB, NEGATIVE_OBJECTION, NOT_RELEVANT:
→ Do NOT include demo link
→ Handle gracefully per the intent

CONFUSED, UNKNOWN:
→ Do NOT include demo link
→ Offer help or clarification

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ANTI-BOT FILTER — HARD CONSTRAINTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ABSOLUTELY FORBIDDEN — any of these = reject the reply:
- "ensure", "streamline", "comprehensive", "value", "leverage", "facilitate"
- "I'd love to", "hope this finds you well", "just wanted to reach out"
- "Let's connect", "schedule a call", "happy to help"
- "Our platform", "innovative", "cutting-edge", "game-changer"
- "Best regards", "Kind regards", "Warm regards"
- Any phrase that sounds like it came from a template

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OUTPUT FORMAT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Return ONLY valid JSON:
{{
  "intent": "INTENT_LABEL",
  "reasoning": "Why you classified this intent",
  "reply_html": "Your reply with {{DEMO_LINK}} placeholder where appropriate. No markdown."
}}
"""

def _groq_analyze_reply(text: str, property_address: str = "your service area", my_name: str = "the team", conversation_state: dict | None = None, gen_params: dict | None = None) -> dict | None:
    """
    Primary intelligence layer.
    Calls Groq to READ the reply, classify intent properly, and generate
    a contextually appropriate response. Returns:
    { intent, reasoning, reply_html }
    Returns None if all keys fail or the model returns unusable output.
    Uses model rotation for rate limit handling.
    """
    global _groq_cursor, _analysis_model_cursor
    if not GROQ_KEYS:
        return None
    
    gp = gen_params or get_generation_params()

    style_mode_instructions = {
        "brief_casual": "Keep it very casual and brief. Like a quick text from a colleague.",
        "observational": "Focus on making a relatable observation about the situation. Don't push.",
        "slightly_curious": "Show a little bit of interest in how they handle things, but keep it light.",
        "very_short": "Be extremely brief. One short sentence maximum."
    }
    style_instr = style_mode_instructions.get(gp['style_mode'], style_mode_instructions['brief_casual'])

    state_str = json.dumps(conversation_state or {}, indent=2)
    system_prompt = _GROQ_SYSTEM_PROMPT.format(
        property_address=property_address,
        my_name=my_name,
        conversation_state=state_str,
        style_mode=gp['style_mode'],
        opener=gp['opener'],
        situation=gp['situation'],
        style_mode_instruction=style_instr,
    )

    # Rotate through all model/key combinations
    max_attempts = len(GROQ_KEYS) * len(ANALYSIS_MODELS)
    for _ in range(max_attempts):
        key = GROQ_KEYS[_groq_cursor % len(GROQ_KEYS)]
        model = ANALYSIS_MODELS[_analysis_model_cursor % len(ANALYSIS_MODELS)]
        _groq_cursor += 1
        
        # Advance model cursor only when we've tried all keys for current model
        if _groq_cursor % len(GROQ_KEYS) == 0:
            _analysis_model_cursor = (_analysis_model_cursor + 1) % len(ANALYSIS_MODELS)
            print(f"[GROQ ANALYZE] Rotating to model: {ANALYSIS_MODELS[_analysis_model_cursor % len(ANALYSIS_MODELS)]}")
        
        try:
            resp = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {key}",
                         "Content-Type":  "application/json"},
                json={
                    "model":  model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user",   "content": f"Analyze this reply:\n\n{text[:1200]}"},
                    ],
                    "temperature": 0.7,
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
                print(f"[GROQ] Key {_groq_cursor-1} rate-limited, trying next model: {model}")
                continue
            else:
                print(f"[GROQ] {resp.status_code}: {resp.text[:120]}")

        except Exception as exc:
            print(f"[GROQ ANALYZE ERROR] {exc}")
            continue

    return None

# Legacy label-only fallback (used only when _groq_analyze_reply fails entirely)
def _groq_classify_llm(text: str) -> str | None:
    """
    Simple classification fallback using model rotation.
    Uses gpt-oss-20b for fast classification, rotates through all models on rate limit.
    """
    global _groq_cursor, _classification_model_cursor
    if not GROQ_KEYS:
        return None
    
    max_attempts = len(GROQ_KEYS) * len(CLASSIFICATION_MODELS)
    for _ in range(max_attempts):
        key = GROQ_KEYS[_groq_cursor % len(GROQ_KEYS)]
        model = CLASSIFICATION_MODELS[_classification_model_cursor % len(CLASSIFICATION_MODELS)]
        _groq_cursor += 1
        
        # Advance model cursor when we've tried all keys for current model
        if _groq_cursor % len(GROQ_KEYS) == 0:
            _classification_model_cursor = (_classification_model_cursor + 1) % len(CLASSIFICATION_MODELS)
            print(f"[GROQ CLASSIFY] Rotating to model: {CLASSIFICATION_MODELS[_classification_model_cursor % len(CLASSIFICATION_MODELS)]}")
        
        try:
            resp = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {key}",
                         "Content-Type":  "application/json"},
                json={
                    "model":  model,
                    "messages": [
                        {"role": "system", "content": (
                            "You classify cold outreach reply intent for a real estate agent.  "
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
                print(f"[GROQ] Key {_groq_cursor-1} rate-limited, trying next model: {model}")
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
_RE_NOT_RELEVANT = re.compile(r"\b(loan officer|mortgage|transaction coordinator|property management|insurance|carpet cleaning|landscaping|home warranty|home automation|security system|renovation|remodeling|pool|pest control)\b", re.I)
_RE_CONFUSED = re.compile(r"\b(what (do you mean|is this|are you expecting|kind of response)|is this a sales|confused|don't understand)\b", re.I)

#── Auditor Frame: New regex patterns for HIGH_NUANCE intents ─────────────────
# STATUS_TEST: Suspicious/guarded tone, testing legitimacy
_RE_STATUS_TEST = re.compile(
    r"\b(what is this|who is this|what company|where did you|why are you emailing|spam|unsolicited|remove me|delete|how'd you get|how did you get|why am i|who gave you)\b",
    re.I
)
# AUTHORITY_SIGNAL: Partner/broker/team mentioned
_RE_AUTHORITY_SIGNAL = re.compile(
    r"\b(my partner|my husband|my wife|my broker|my manager|my team|our team|my supervisor|my boss|with my colleague|cc'd|cc:|forwarded|need to check with)\b",
    re.I
)
# PAIN_AWARE: Explicitly admits to losing leads, response lag, missed deals
_RE_PAIN_AWARE = re.compile(
    r"\b(lose (the |a |)(lead|deal)|miss (the |a |)(lead|email|message)|response time|slow to respond|lag|fall behind|last (lead|deal)|lost (a |the |)(lead|deal)|never respond|can't keep up|overwhelmed|i.?m busy|i don.?t have time)\b",
    re.I
)

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
    
    # HIGH_NUANCE intents (Auditor Frame) — checked first for precision
    if _RE_STATUS_TEST.search(t):
        return 'STATUS_TEST'
    
    if _RE_AUTHORITY_SIGNAL.search(t):
        return 'AUTHORITY_SIGNAL'
    
    if _RE_PAIN_AWARE.search(t):
        return 'PAIN_AWARE'
    
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

#── Auto-reply templates (Real Estate Agent Fallbacks) ────────────────────────
def _tmpl_ps() -> str:
    return "\n\nP.S. If you'd rather not hear from me, just let me know and I'll hop off your inbox."

def _tmpl_asks_identity(my_name: str, gp: dict, demo_link: str = None) -> str:
    link = demo_link or 'https://replyzeai.com/goods/templates/demo'
    body = f"I'm {my_name}. We handle inbound leads instantly when you're busy {gp['situation']}. Quick overview: {link}"
    return f"{body}\n\n— {my_name}"

def _tmpl_agent_handles(my_name: str, gp: dict, demo_link: str = None) -> str:
    """Concierge response for agents who handle their own replies."""
    if demo_link:
        return f"{gp['opener']} Makes sense. Here's a quick look: {demo_link}\n\n— {my_name}"
    return f"{gp['opener']} Makes sense. Worth a look: https://replyzeai.com/goods/templates/demo\n\n— {my_name}"

def _tmpl_nobody_handles(my_name: str, gp: dict, demo_link: str = None) -> str:
    """Concierge response for leads who admit they miss leads."""
    if demo_link:
        return f"{gp['opener']} That's where it gets costly — the lead just emails the next agent. Here's how we fix it: {demo_link}\n\n— {my_name}"
    return f"{gp['opener']} That's where it gets costly — the lead just emails the next agent. Here's how we fix it: https://replyzeai.com/goods/templates/demo\n\n— {my_name}"

def _tmpl_assistant_handles(my_name: str, gp: dict, demo_link: str = None) -> str:
    """Concierge response for leads with assistant/team support."""
    if demo_link:
        return f"{gp['opener']} Helpful to have support. Sometimes things still slip through though. Quick overview: {demo_link}\n\n— {my_name}"
    return f"{gp['opener']} Helpful to have support. Sometimes things still slip through though. Quick overview: https://replyzeai.com/goods/templates/demo\n\n— {my_name}"

def _tmpl_interested(my_name: str, gp: dict, demo_link: str = None) -> str:
    """Concierge response for interested leads — deliver the demo."""
    if demo_link:
        return f"Great! Here's a quick demo: {demo_link}\n\n— {my_name}"
    return f"Great! Here's a quick demo: https://replyzeai.com/goods/templates/demo\n\n— {my_name}"

def _tmpl_asks_price(my_name: str, gp: dict, demo_link: str = None) -> str:
    """Concierge response for price questions — deliver the demo."""
    if demo_link:
        return f"It depends on your volume, but it usually pays for itself with the first saved lead. Here's a quick example: {demo_link}\n\n— {my_name}"
    return f"It depends on your volume, but it usually pays for itself with the first saved lead. Here's a quick example: https://replyzeai.com/goods/templates/demo\n\n— {my_name}"

def _tmpl_asks_details(my_name: str, gp: dict, demo_link: str = None) -> str:
    """Concierge response for detail questions — deliver the demo."""
    if demo_link:
        return f"Zero manual work for you. Here's how it works: {demo_link}\n\n— {my_name}"
    return f"Zero manual work for you. Here's how it works: https://replyzeai.com/goods/templates/demo\n\n— {my_name}"

def _tmpl_not_relevant(my_name: str, property_address: str, gp: dict) -> str:
    """Not relevant — no demo link."""
    body = f"{gp['opener']} Looks like you might be in a different type of business — we're specifically looking for real estate agents."
    return f"{body}\n\n— {my_name}"

def _tmpl_confused(my_name: str, property_address: str, gp: dict) -> str:
    """Confused — no demo link, offer help."""
    body = f"Sorry for the confusion! We help real estate agents respond to inbound leads faster. Happy to clarify if you have questions."
    return f"{body}\n\n— {my_name}"

def _tmpl_pass_unsub() -> str:
    """Unsubscribe — no demo link."""
    return "Understood — removing you from our list now. Good luck with the listings!"

def _tmpl_negative_objection() -> str:
    """Negative objection — no demo link."""
    return "I apologize for the confusion. I'll correct my records right away and won't reach out again."

def _tmpl_acknowledgment_only(my_name: str, gp: dict, demo_link: str = None) -> str:
    """Concierge response for acknowledgments — deliver the demo."""
    if demo_link:
        return f"{gp['opener']} Quick overview for you: {demo_link}\n\n— {my_name}"
    return f"{gp['opener']} Quick overview for you: https://replyzeai.com/goods/templates/demo\n\n— {my_name}"

def _tmpl_unknown(my_name: str, gp: dict) -> str:
    """Unknown intent — no demo link."""
    return f"{gp['opener']} Thanks — got your message. I'll get back to you with more details shortly.\n\n— {my_name}"

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
                 .select('id,email,name,do_not_contact,open_house,reply_count,product_introduced,last_intent,belief_variant') \
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

    property_address = lead.get('open_house') or "your service area"
    my_name = account.get('display_name') or "the team"

    analysis = _analyze_and_handle_reply(
        from_email=from_email, body_text=body_text, lead=lead,
        my_name=my_name, property_address=property_address,
        msg_id=orig_msg_id, channel="smtp_imap"
    )

    intent      = analysis['intent']
    reasoning   = analysis['reasoning']
    groq_result = analysis['groq_result']
    gp          = analysis['gp']
    demo_link   = analysis['demo_link']
    queue_ids   = analysis['queue_ids']

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

    # ── Step 6: Choose reply ───────────────────────────────────────────────────
    groq_reply   = (groq_result or {}).get("reply_html", "").strip()
    reply_html: str | None = None

    if intent == 'PASS_UNSUB':
        reply_html = groq_reply or _tmpl_pass_unsub()
        _handle_unsub(from_email)
        _log_audit('UNSUBSCRIBED', {'email': from_email})

    elif intent == 'NEGATIVE_OBJECTION':
        reply_html = groq_reply or _tmpl_negative_objection()
        _handle_unsub(from_email)
        _log_audit('NEGATIVE_OBJECTION', {
            'from': from_email, 'reasoning': reasoning, 'account': account['email'],
        })

    elif intent == 'NOT_RELEVANT':
        reply_html = groq_reply or _tmpl_not_relevant(my_name, property_address, gp)
        _log_audit('NOT_RELEVANT', {
            'from': from_email, 'account': account['email'],
        })
        _update_lead_status(from_email, 'not_relevant')

    elif intent == 'CONFUSED':
        reply_html = groq_reply or _tmpl_confused(my_name, property_address, gp)
        _log_audit('CONFUSED', {
            'from': from_email, 'account': account['email'],
        })
        _update_lead_status(from_email, 'confused')

    else:
        # All positive/neutral intents: Groq reply first, then inject demo link
        reply_html = groq_reply

        if not reply_html:
            # Fall back to templates with demo link
            if intent == 'INTERESTED':
                reply_html = _tmpl_interested(my_name, gp, demo_link)
            elif intent == 'PAIN_AWARE':
                reply_html = _tmpl_nobody_handles(my_name, gp, demo_link)
            elif intent == 'ACKNOWLEDGMENT_ONLY':
                reply_html = _tmpl_acknowledgment_only(my_name, gp, demo_link)
            elif intent == 'ASKS_PRICE':
                reply_html = _tmpl_asks_price(my_name, gp, demo_link)
            elif intent == 'ASKS_DETAILS':
                reply_html = _tmpl_asks_details(my_name, gp, demo_link)
            elif intent == 'ASKS_IDENTITY':
                reply_html = _tmpl_asks_identity(my_name, gp).replace(
                    'https://replyzeai.com/goods/templates/demo',
                    demo_link or 'https://replyzeai.com/goods/templates/demo'
                )
            elif intent == 'AGENT_HANDLES':
                reply_html = _tmpl_agent_handles(my_name, gp, demo_link)
            elif intent == 'NOBODY_HANDLES':
                reply_html = _tmpl_nobody_handles(my_name, gp, demo_link)
            elif intent == 'ASSISTANT_HANDLES':
                reply_html = _tmpl_assistant_handles(my_name, gp, demo_link)
            else:
                reply_html = _tmpl_unknown(my_name, gp)

        # Inject demo link if Groq reply contains {DEMO_LINK} or {{DEMO_LINK}} placeholder
        if demo_link and reply_html:
            if '{{DEMO_LINK}}' in reply_html:
                reply_html = reply_html.replace('{{DEMO_LINK}}', demo_link)
                print(f"  [{from_email}] Demo link injected ({{{{DEMO_LINK}}}} pattern)")
            elif '{DEMO_LINK}' in reply_html:
                reply_html = reply_html.replace('{DEMO_LINK}', demo_link)
                print(f"  [{from_email}] Demo link injected ({{DEMO_LINK}} pattern)")

        # Log DEMO_DELIVERED handoff notification
        if demo_link and intent in DEMO_LINK_INTENTS:
            _log_audit('DEMO_DELIVERED', {
                "from":       from_email,
                "lead_id":    lead['id'],
                "intent":     intent,
                "demo_link":  demo_link,
                "account":    account['email'],
            })
            _update_lead_status(from_email, f'{intent.lower()}_demo_sent')

        _log_audit(f'REPLY_{intent}', {
            'from': from_email, 'reasoning': reasoning, 'account': account['email'],
        })

    # ── Step 7: Enqueue reply ─────────────────────────────────────────────────
    _store_responded_lead(lead['id'], from_email, intent, body_text)
    _clear_pending_followups(lead['id'])

    auto_reply_sent = False
    if reply_html:
        _enqueue_auto_reply(
            lead=lead,
            account_email=account['email'],
            subject=subject,
            body=reply_html,
            in_reply_to=orig_msg_id,
            references=references
        )
        auto_reply_sent = True

    # Determine if product was introduced in this reply
    pitched = (intent in ['INTERESTED', 'ASKS_PRICE', 'ASKS_DETAILS']) or (lead.get('product_introduced', False))
    _update_lead_state(lead['id'], intent, product_introduced=pitched)

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
        supabase.table("responded_leads").insert({
            "email":        email,
            "original_lead_id": lead_id,
            "intent":       intent,
            "raw_reply":    raw_reply[:1000],
            "responded_at": datetime.now(timezone.utc).isoformat(),
        }, on_conflict="email").execute()
    except:
        pass

def _get_random_delay() -> datetime:
    """Calculate randomized delay based on work hours (America/Chicago)."""
    tz = pytz.timezone('America/Chicago')
    now_tz = datetime.now(tz)

    # Work hours: 8 AM - 6 PM
    is_work_hours = 8 <= now_tz.hour < 18

    if is_work_hours:
        rand = random.random()
        if rand < 0.70:
            minutes = random.uniform(2, 12)
        elif rand < 0.85:
            minutes = random.uniform(12, 18)
        else:
            minutes = random.uniform(25, 40)
    else:
        # After hours: 30 sec - 5 mins
        minutes = random.uniform(0.5, 5)

    return datetime.now(timezone.utc) + timedelta(minutes=minutes)

def _enqueue_auto_reply(lead: dict, account_email: str, subject: str, body: str,
                        thread_id: str = None, in_reply_to: str = None, references: str = None):
    """Enqueue the auto-reply in the email_queue for later delivery."""
    scheduled_for = _get_random_delay()

    # Ensure subject starts with Re:
    if not subject.lower().startswith("re:"):
        subject = f"Re: {subject}"

    try:
        supabase.table("email_queue").insert({
            "lead_id": lead['id'],
            "lead_email": lead['email'],
            "subject": subject,
            "body": body,
            "scheduled_for": scheduled_for.isoformat(),
            "sequence": 999, # High sequence to avoid triggering further follow-ups
            "sent_from": account_email,
            "thread_id": thread_id,
            "in_reply_to": in_reply_to,
            "references": references
        }).execute()
        print(f"  [ENQUEUED] Auto-reply for {lead['email']} at {scheduled_for.isoformat()}")
    except Exception as e:
        print(f"[ENQUEUE ERROR] {e}")

def _update_lead_state(lead_id: int, intent: str, product_introduced: bool = False, belief_variant: str = None):
    """Update conversation state on the lead."""
    try:
        # Fetch current state
        lead_r = supabase.table("leads").select("reply_count, product_introduced, belief_variant").eq("id", lead_id).single().execute()
        if not lead_r.data:
            return

        current_count = lead_r.data.get("reply_count", 0) or 0
        already_introduced = lead_r.data.get("product_introduced", False)
        existing_variant = lead_r.data.get("belief_variant")

        update_data = {
            "reply_count": current_count + 1,
            "last_intent": intent,
            "last_auto_reply_at": datetime.now(timezone.utc).isoformat(),
            "responded": True,
            "responded_at": datetime.now(timezone.utc).isoformat(),
        }

        if product_introduced or already_introduced:
            update_data["product_introduced"] = True

        if belief_variant and not existing_variant:
            update_data["belief_variant"] = belief_variant
            update_data["belief_assigned_at"] = datetime.now(timezone.utc).isoformat()

        supabase.table("leads").update(update_data).eq("id", lead_id).execute()
    except Exception as e:
        print(f"[UPDATE LEAD STATE ERROR] {e}")

def _clear_pending_followups(lead_id: int):
    """Remove any unsent follow-ups from the queue for this lead."""
    try:
        supabase.table("email_queue").delete().eq("lead_id", lead_id).is_("sent_at", "null").execute()
    except Exception as e:
        print(f"[CLEAR FOLLOWUPS ERROR] {e}")

def _analyze_and_handle_reply(from_email: str, body_text: str, lead: dict, my_name: str, property_address: str, msg_id: str, thread_id: str = None, channel: str = "gmail"):
    """
    Shared logic for analyzing a reply and generating the response.
    Used by both Gmail and IMAP paths.
    """
    gp = get_generation_params()

    # ── Step 1: Lookup email_queue for demo link IDs ──────────────────────────
    queue_ids = _get_email_queue_ids(from_email)
    demo_link = None
    if queue_ids:
        demo_link = _build_demo_link(
            lead_id=queue_ids['lead_id'],
            campaign_id=queue_ids['campaign_id'],
            eqid=queue_ids['eqid']
        )
        print(f"  [{from_email}] Demo link: {demo_link}")
    else:
        print(f"  [{from_email}] No email_queue entry found — demo link unavailable")

    conversation_state = {
        "reply_count": lead.get("reply_count", 0),
        "product_introduced": lead.get("product_introduced", False),
        "last_intent": lead.get("last_intent")
    }

    # ── Step 2: Groq analyze ──────────────────────────────────────────────────
    print(f"  [{from_email}] calling Groq analyze ({channel}) …")
    groq_result = _groq_analyze_reply(
        body_text, property_address=property_address, my_name=my_name,
        conversation_state=conversation_state, gen_params=gp
    )

    # ── Step 3: Final intent ──────────────────────────────────────────────────
    intent     = classify_intent(body_text, groq_result)
    reasoning  = groq_result.get('reasoning', '') if groq_result else ''
    confidence = 0.9 if groq_result else 0.5
    print(f"  [{from_email}] intent={intent}")

    # ── Step 4: Decision Logging ──────────────────────────────────────────────
    metadata = groq_result or {}
    metadata.update({
        "intent":    intent,
        "lead_id":   lead['id'],
        "thread_id": thread_id,
        "msg_id":    msg_id,
        "channel":   channel,
        "demo_link": demo_link,
    })

    _log_agent_decision(
        from_email=from_email, intent=intent, confidence=confidence,
        reasoning=reasoning, metadata=metadata,
    )

    return {
        "intent":     intent,
        "reasoning":  reasoning,
        "groq_result": groq_result,
        "gp":         gp,
        "demo_link":  demo_link,
        "queue_ids":  queue_ids,
    }

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
                 .select("id,email,name,do_not_contact,open_house,reply_count,product_introduced,last_intent,belief_variant") \
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

    property_address = lead.get('open_house') or "your service area"
    my_name = account.get('display_name') or "the team"

    analysis = _analyze_and_handle_reply(
        from_email=from_email, body_text=body_text, lead=lead,
        my_name=my_name, property_address=property_address,
        msg_id=gmail_msg_id, thread_id=thread_id, channel="gmail"
    )

    intent      = analysis['intent']
    reasoning   = analysis['reasoning']
    groq_result = analysis['groq_result']
    gp          = analysis['gp']
    demo_link   = analysis['demo_link']
    queue_ids   = analysis['queue_ids']

    _log_audit('REPLY_RECEIVED', {
        "from":        from_email,
        "subject":     subject,
        "intent":      intent,
        "reasoning":   reasoning,
        "raw_snippet": body_text[:300],
        "gmail_msg_id": gmail_msg_id,
        "account":     account['email'],
    })

    # ── Step 6: Choose reply ───────────────────────────────────────────────────
    groq_reply   = (groq_result or {}).get("reply_html", "").strip()
    reply_html: str | None = None

    if intent == 'PASS_UNSUB':
        reply_html = groq_reply or _tmpl_pass_unsub()
        _handle_unsub(from_email)
        _log_audit('UNSUBSCRIBED', {"email": from_email})

    elif intent == 'NEGATIVE_OBJECTION':
        reply_html = groq_reply or _tmpl_negative_objection()
        _handle_unsub(from_email)
        _log_audit('NEGATIVE_OBJECTION', {
            "from":      from_email,
            "reasoning": reasoning,
            "account":   account['email'],
        })

    elif intent == 'NOT_RELEVANT':
        reply_html = groq_reply or _tmpl_not_relevant(my_name, property_address, gp)
        _log_audit('NOT_RELEVANT', {
            "from":    from_email,
            "account": account['email'],
        })
        _update_lead_status(from_email, 'not_relevant')

    elif intent == 'CONFUSED':
        reply_html = groq_reply or _tmpl_confused(my_name, property_address, gp)
        _log_audit('CONFUSED', {
            "from":    from_email,
            "account": account['email'],
        })
        _update_lead_status(from_email, 'confused')

    else:
        # All positive/neutral intents: Groq reply first, then inject demo link
        reply_html = groq_reply

        if not reply_html:
            # Fall back to templates with demo link
            if intent == 'INTERESTED':
                reply_html = _tmpl_interested(my_name, gp, demo_link)
            elif intent == 'PAIN_AWARE':
                reply_html = _tmpl_nobody_handles(my_name, gp, demo_link)  # Reuse template
            elif intent == 'ACKNOWLEDGMENT_ONLY':
                reply_html = _tmpl_acknowledgment_only(my_name, gp, demo_link)
            elif intent == 'ASKS_PRICE':
                reply_html = _tmpl_asks_price(my_name, gp, demo_link)
            elif intent == 'ASKS_DETAILS':
                reply_html = _tmpl_asks_details(my_name, gp, demo_link)
            elif intent == 'ASKS_IDENTITY':
                reply_html = _tmpl_asks_identity(my_name, gp).replace(
                    'https://replyzeai.com/goods/templates/demo', 
                    demo_link or 'https://replyzeai.com/goods/templates/demo'
                )
            elif intent == 'AGENT_HANDLES':
                reply_html = _tmpl_agent_handles(my_name, gp, demo_link)
            elif intent == 'NOBODY_HANDLES':
                reply_html = _tmpl_nobody_handles(my_name, gp, demo_link)
            elif intent == 'ASSISTANT_HANDLES':
                reply_html = _tmpl_assistant_handles(my_name, gp, demo_link)
            else:
                reply_html = _tmpl_unknown(my_name, gp)

        # Inject demo link if Groq reply contains {DEMO_LINK} or {{DEMO_LINK}} placeholder
        if demo_link and reply_html:
            if '{{DEMO_LINK}}' in reply_html:
                reply_html = reply_html.replace('{{DEMO_LINK}}', demo_link)
                print(f"  [{from_email}] Demo link injected ({{{{DEMO_LINK}}}} pattern)")
            elif '{DEMO_LINK}' in reply_html:
                reply_html = reply_html.replace('{DEMO_LINK}', demo_link)
                print(f"  [{from_email}] Demo link injected ({{DEMO_LINK}} pattern)")

        # Log DEMO_DELIVERED handoff notification
        if demo_link and intent in DEMO_LINK_INTENTS:
            _log_audit('DEMO_DELIVERED', {
                "from":       from_email,
                "lead_id":    lead['id'],
                "intent":     intent,
                "demo_link":  demo_link,
                "account":    account['email'],
            })
            _update_lead_status(from_email, f'{intent.lower()}_demo_sent')

        _log_audit(f'REPLY_{intent}', {
            "from":      from_email,
            "reasoning": reasoning,
            "account":   account['email'],
        })

    # ── Step 7: Enqueue reply ─────────────────────────────────────────────────
    _store_responded_lead(lead['id'], from_email, intent, body_text)
    _clear_pending_followups(lead['id'])

    auto_reply_sent = False
    if reply_html:
        _enqueue_auto_reply(
            lead=lead,
            account_email=account['email'],
            subject=subject,
            body=reply_html,
            thread_id=thread_id,
            in_reply_to=orig_msg_id,
            references=orig_msg_id
        )
        auto_reply_sent = True

    # Determine if product was introduced in this reply
    pitched = (intent in ['INTERESTED', 'ASKS_PRICE', 'ASKS_DETAILS']) or (lead.get('product_introduced', False))

    _update_lead_state(lead['id'], intent, product_introduced=pitched)

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
