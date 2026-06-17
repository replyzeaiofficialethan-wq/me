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

#── Phrase Randomization Pools ───────────────────────────────────────────────
OPENERS = [
    "Makes sense.",
    "Yeah, fair enough.",
    "Gotcha.",
    "That tracks.",
    "Right.",
    "Exactly."
]

BELIEF_QUESTIONS = [
    "Out of curiosity, how much do you think response time matters when a lead emails you during a showing? Some agents tell me it's huge — others say leads just email the next agent.",
    "Random question — do you think the first agent to respond to a lead usually gets the deal, or do people still shop around after?"
]

BELIEF_QUESTION_RATE = 0.5

BELIEF_SIGNALS = ['BELIEF_HIGH', 'BELIEF_MEDIUM', 'BELIEF_LOW', 'BELIEF_UNKNOWN']

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
        "ask_question": random.random() < 0.35  # 30-40% probability
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

#── Real Estate Agent Intent Classification ────────────────────────────────────
# Intents marked as HIGH_NUANCE require LLM-generated replies only (no template fallback)
HIGH_NUANCE_INTENTS = {'STATUS_TEST', 'AUTHORITY_SIGNAL', 'PAIN_AWARE'}

_GROQ_VALID_INTENTS = {
    'AGENT_HANDLES', 'NOBODY_HANDLES', 'ASSISTANT_HANDLES', 'INTERESTED',
    'ASKS_PRICE', 'ASKS_DETAILS', 'ASKS_IDENTITY', 'ACKNOWLEDGMENT_ONLY',
    'PASS_UNSUB', 'NEGATIVE_OBJECTION', 'NOT_RELEVANT', 'CONFUSED', 'UNKNOWN',
    # New Auditor Frame intents
    'STATUS_TEST', 'AUTHORITY_SIGNAL', 'PAIN_AWARE'
}

#── System prompt: THE AUDITOR FRAME ─────────────────────────────────────────
_GROQ_SYSTEM_PROMPT = """
You are an AUDITOR, not a salesperson.

Your job is to diagnose "Lead-Leak" — the revenue lost when real estate agents miss or slow-respond to inbound leads while they're at showings, driving between properties, or otherwise unavailable.

Before you do ANYTHING else, you must complete the PSYCHOLOGICAL PROFILING section in your internal reasoning. This is mandatory and shapes your entire response.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 1: PSYCHOLOGICAL PROFILING (MANDATORY — think through these)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

a) STATUS TEST CHECK: Is the lead testing if you're legitimate?
   - "What is this?" / "Who is this?" / "Where did you get my email?"
   - Short, terse, clipped sentences
   - Suspicious or guarded tone
   → If YES, you are being evaluated. Do NOT explain the product. Diagnose the pain instead.

b) POWER DYNAMIC CHECK: Is there an authority figure involved?
   - CC'd partner, broker, team lead, or assistant
   - "My assistant handles that" / "My broker wants to know..."
   - "We need to discuss this as a team"
   → If YES, acknowledge the authority structure. Pivot to office-wide ROI.

c) TENSION LEVEL ANALYSIS:
   - HIGH TENSION: Short sentences, single words, curt replies ("I do", "No", "Stop")
   - LOW TENSION: Longer explanations, multiple sentences, relaxed tone
   → Match their energy. Mirror their length exactly.

d) PAIN SIGNAL CHECK: Are they already aware of the problem?
   - "I miss leads all the time" / "Response time kills me" / "We lose deals to faster agents"
   → If PAIN_AWARE, skip the pitch. They're already sold on the problem.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 2: THE AUDITOR FRAME — RULES BY INTENT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

STATUS_TEST:
- DO NOT explain what the service is
- Instead, diagnose the lead-leak problem directly
- Example: "Simple: most agents lose ~20% of their leads during showings because they can't reply in 2 minutes. We plug that hole."
- Match their brevity. If they sent 5 words, reply with 10 words max.
- Authority signal: If they ask "who is this," just give your first name, don't explain the company.

AUTHORITY_SIGNAL (partner/broker/team involved):
- Acknowledge the team/partner explicitly: "Tell your partner I said hi."
- Pivot to OFFICE efficiency: "Most teams we work with have the same issue — the whole office loses when one agent is tied up."
- DO NOT pitch to just one person when a team is involved.

PAIN_AWARE:
- Skip the discovery questions entirely
- They already feel the pain — go straight to validation + soft next step
- Example: "Yeah, that lag kills. We see it all the time. Happy to show you how we handle it for a week, on us."
- Only offer free trial if they're PAIN_AWARE OR explicitly INTERESTED. Never on first contact otherwise.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 3: ANTI-BOT FILTER — HARD CONSTRAINTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ABSOLUTELY FORBIDDEN — any of these = reject the reply:
- "ensure", "streamline", "comprehensive", "value", "leverage", "facilitate"
- "I'd love to", "hope this finds you well", "just wanted to reach out"
- "Let's connect", "schedule a call", "happy to help"
- "Our platform", "innovative", "cutting-edge", "game-changer"
- "Best regards", "Kind regards", "Warm regards"
- Any phrase that sounds like it came from a template

BREVITY MIRRORING (non-negotiable):
- They sent 1 sentence → you send 1 sentence
- They sent 3 words → you send ~6 words max
- Exception: If they're PAIN_AWARE, you can go slightly longer to validate their pain

NO "BEGGAR ENERGY":
- Free trial is NOT offered unless:
  a) Intent is INTERESTED, PAIN_AWARE, or ASKS_PRICE/DETAILS, OR
  b) Belief signal is BELIEF_HIGH AND intent is AGENT_HANDLES
- Never say "would you like to try it free?" — it sounds desperate
- If offering: "We can run your next batch free" or "Worth a test run on your next few leads"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 4: INTENT CLASSIFICATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Classify into ONE of these labels:

AGENT_HANDLES      : They handle replies themselves (e.g., "Me", "I do", "I answer").
NOBODY_HANDLES     : Nobody handles it, they miss leads, it's a problem.
ASSISTANT_HANDLES  : They have assistant/team/coordinator handling inbound.
INTERESTED         : Explicitly interested, wants to know more.
ASKS_PRICE         : Asking about pricing/cost.
ASKS_DETAILS       : Asking how the system works.
ASKS_IDENTITY      : Asking who you are (use STATUS_TEST logic instead).
NOT_RELEVANT       : Not a real estate agent.
CONFUSED           : Doesn't understand the email's purpose.
ACKNOWLEDGMENT_ONLY: Brief non-action reply ("got it", "ok").
PASS_UNSUB         : Explicitly declining/removal request.
NEGATIVE_OBJECTION : Upset, frustrated, or angry.
UNKNOWN            : Cannot determine intent.

// NEW AUDITOR FRAME INTENTS (HIGH_NUANCE — use LLM reply only, no templates):
STATUS_TEST        : Testing legitimacy with "What is this?", "Who is this?", or suspicious/guarded tone.
AUTHORITY_SIGNAL   : Partner/broker/team mentioned or CC'd; power dynamic involved.
PAIN_AWARE         : Explicitly admits to losing leads, response lag, or missed deals.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
STEP 5: BELIEF SIGNAL
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

BELIEF_HIGH   : Response time = deals ("First responder usually wins", "Speed is everything")
BELIEF_MEDIUM : Matters but isn't everything ("Relationships matter too", "Price matters more")
BELIEF_LOW    : Doesn't think speed matters much ("Leads wait", "Reputation wins")
BELIEF_UNKNOWN: Off-topic or unclear about speed beliefs

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OUTPUT FORMAT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Return ONLY valid JSON:
{{
  "lead_psychology": "2-3 sentences on what you observed about their status/power dynamic/tension/psychological state",
  "intent": "INTENT_LABEL",
  "belief_signal": "BELIEF_SIGNAL_LABEL",
  "reasoning": "Why you classified this intent",
  "reply_html": "Your reply only — no markdown, no explanation. Plain text with {my_name} signature."
}}
"""

def _groq_analyze_reply(text: str, property_address: str = "your service area", my_name: str = "the team", conversation_state: dict | None = None, gen_params: dict | None = None, variant_tag: str | None = None, chosen_question: str | None = None) -> dict | None:
    """
    Primary intelligence layer.
    Calls Groq to READ the reply, classify intent properly, and generate
    a contextually appropriate response. Returns:
    { intent, belief_signal, reasoning, reply_html }
    Returns None if all keys fail or the model returns unusable output.
    """
    global _groq_cursor
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

    variant_instructions = ""
    if variant_tag == "group_a_observation":
        variant_instructions = f"""
VARIANT A INSTRUCTIONS:
- Start exactly with: "{gp['opener']}"
- Make one short observation about how common or respectable their stance is.
- Do NOT ask a question.
- Keep the response under 2 sentences.
- No AI/software jargon.
"""
    elif variant_tag == "group_b_belief_question" and chosen_question:
        variant_instructions = f"""
VARIANT B INSTRUCTIONS:
- Start exactly with: "{gp['opener']}"
- Append this question exactly as written verbatim: "{chosen_question}"
- Do NOT change any words in the question.
- Do NOT add another question or extra sentences.
- Keep the tone casual, like an iPhone text.
- Under 3 sentences total.
"""

    state_str = json.dumps(conversation_state or {}, indent=2)
    system_prompt = _GROQ_SYSTEM_PROMPT.format(
        property_address=property_address,
        my_name=my_name,
        conversation_state=state_str,
        style_mode=gp['style_mode'],
        opener=gp['opener'],
        situation=gp['situation'],
        ask_question=gp['ask_question'],
        style_mode_instruction=style_instr,
        variant_instructions=variant_instructions
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
                belief_signal = parsed.get("belief_signal", "BELIEF_UNKNOWN").strip().upper()
                if intent in _GROQ_VALID_INTENTS:
                    return {
                        "intent":          intent,
                        "belief_signal":   belief_signal if belief_signal in BELIEF_SIGNALS else "BELIEF_UNKNOWN",
                        "lead_psychology": parsed.get("lead_psychology", "")[:500],
                        "reasoning":       parsed.get("reasoning", "")[:500],
                        "reply_html":      parsed.get("reply_html", "")[:1000],
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

def _tmpl_asks_identity(my_name: str, gp: dict) -> str:
    body = f"{gp['opener']} We help with speed-to-lead by handling inbound client leads instantly when you're busy {gp['situation']}. "
    body += "We can actually handle your next 5-10 client leads free so you see how it works — zero risk."
    return f"{body}\n\n— {my_name}"

def _tmpl_agent_handles(my_name: str, gp: dict, variant_tag: str = None, chosen_question: str = None) -> str:
    """Value-First: Contrast Bridge approach — acknowledge, contrast with lead-leak risk, soft close."""
    if variant_tag == "group_a_observation":
        return f"{gp['opener']} Most agents handle it themselves, but the lead-leak still happens {gp['situation']}. We stopped that. Worth a 2-min look?\n\n— {my_name}"
    elif variant_tag == "group_b_belief_question" and chosen_question:
        return f"{gp['opener']} Most agents handle it themselves, but the lead-leak still happens {gp['situation']}. We stopped that.\n\n{chosen_question}\n\n— {my_name}"

    # Default legacy fallback if no variant is specified
    if gp['style_mode'] == 'very_short':
        return f"{gp['opener']} Most agents handle it themselves, but the lead-leak still happens {gp['situation']}. We stopped that. Worth a 2-min look?\n\n— {my_name}"

    body = f"{gp['opener']} Most agents handle it themselves, but the lead-leak still happens {gp['situation']}. We stopped that."
    if gp['ask_question']:
        body += "\n\nWorth a 2-min look?"
    return f"{body}\n\n— {my_name}"

def _tmpl_nobody_handles(my_name: str, gp: dict) -> str:
    body = f"{gp['opener']} Missed leads usually mean lost deals — especially {gp['situation']}, the lead just emails the next agent."
    if gp['ask_question']:
        body += "\n\nDo leads ever sit for a bit during busy hours or do you usually get to them pretty fast?"
    return f"{body}\n\n— {my_name}"

def _tmpl_assistant_handles(my_name: str, gp: dict) -> str:
    body = f"{gp['opener']} A lot of agents I talk to already have someone handling the inbox."
    if gp['ask_question']:
        body += f"\n\nOut of curiosity, do leads ever still slip through {gp['situation']} or is response time pretty locked in?"
    return f"{body}\n\n— {my_name}"

def _tmpl_interested(my_name: str, gp: dict) -> str:
    body = f"Mainly helps with response time. If someone emails {gp['situation']}, they get an instant response until you jump back in."
    body += "\n\nWanna try it on your next batch of client leads free? We can run 5-10 at no cost so you see the difference."
    return f"{body}\n\n— {my_name}"

def _tmpl_asks_price(my_name: str, gp: dict) -> str:
    """Assertive Price Pivot — direct value statement, no deflecting."""
    body = f"{gp['opener']} It depends on your volume, but it usually pays for itself with the first saved lead. Want to see a quick example of how it works for your listings?"
    return f"{body}\n\n— {my_name}"

def _tmpl_asks_details(my_name: str, gp: dict) -> str:
    body = f"It's zero manual work for you. We help with speed-to-lead so client leads get answered {gp['situation']} while you're busy."
    if gp['ask_question']:
        body += "\n\nHappy to show you how it works if helpful?"
    return f"{body}\n\n— {my_name}"

def _tmpl_not_relevant(my_name: str, property_address: str, gp: dict) -> str:
    body = f"{gp['opener']} Looks like you might be in a different type of business — we're specifically looking for real estate agents."
    if gp['ask_question']:
        body += "\n\nDo you happen to do any real estate on the side?"
    return f"{body}\n\n— {my_name}"

def _tmpl_confused(my_name: str, property_address: str, gp: dict) -> str:
    body = f"Sorry for the confusion! We were asking about how you handle inbound leads — like when someone's ready to tour a property or has a question about a listing."
    if gp['ask_question']:
        body += "\n\nDo you usually get to those right away or once you're done showing?"
    return f"{body}\n\n— {my_name}"

def _tmpl_pass_unsub() -> str:
    return (
        "Understood — removing you from our list now. "
        "Good luck with the listings!"
    )

def _tmpl_negative_objection() -> str:
    return (
        "I apologize for the confusion. I'll correct my records right away and won't reach out again."
    )

def _tmpl_acknowledgment_only(my_name: str, gp: dict) -> str:
    """Pattern Interrupt — re-engage with high-leverage curiosity question."""
    body = f"{gp['opener']} Fair enough. Just curious — do you think the first agent to respond usually wins the deal, or do people still shop around?"
    return f"{body}\n\n— {my_name}"

def _tmpl_unknown(my_name: str, gp: dict) -> str:
    return (
        f"{gp['opener']} Thanks — got your message. I'll get back to you with more details shortly.\n\n— {my_name}"
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

    intent          = analysis['intent']
    reasoning       = analysis['reasoning']
    variant_tag     = analysis['variant_tag']
    chosen_question = analysis['chosen_question']
    groq_result     = analysis['groq_result']
    gp              = analysis['gp']

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

    # ── Step 6: Choose reply (mirrors Gmail path exactly) ─────────────────────
    groq_reply          = (groq_result or {}).get('reply_html', '').strip()
    reply_html: str | None = None

    # ── HIGH_NUANCE Intents: LLM reply ONLY — no template fallback ─────────────
    if intent in HIGH_NUANCE_INTENTS:
        # These require high-nuance mirroring that must come solely from the LLM
        if not groq_reply:
            # If LLM failed, fall back to a minimal safe response
            groq_reply = _tmpl_unknown(my_name, gp)
        reply_html = groq_reply
        _log_audit(f'HIGH_NUANCE_{intent}', {
            'from': from_email, 'account': account['email'],
            'lead_psychology': groq_result.get('lead_psychology', '') if groq_result else '',
        })
        _update_lead_status(from_email, intent.lower())

    elif intent == 'AGENT_HANDLES':
        reply_html = groq_reply or _tmpl_agent_handles(my_name, gp, variant_tag=variant_tag, chosen_question=chosen_question)
        _log_audit('AGENT_HANDLES', {
            'from': from_email, 'account': account['email'],
        })
        _update_lead_status(from_email, 'agent_handles')

    elif intent == 'NOBODY_HANDLES':
        reply_html = groq_reply or _tmpl_nobody_handles(my_name, gp)
        _log_audit('NOBODY_HANDLES', {
            'from': from_email, 'account': account['email'],
        })
        _update_lead_status(from_email, 'nobody_handles')

    elif intent == 'ASSISTANT_HANDLES':
        reply_html = groq_reply or _tmpl_assistant_handles(my_name, gp)
        _log_audit('ASSISTANT_HANDLES', {
            'from': from_email, 'account': account['email'],
        })
        _update_lead_status(from_email, 'assistant_handles')

    elif intent == 'INTERESTED':
        reply_html = groq_reply or _tmpl_interested(my_name, gp)
        _log_audit('INTERESTED', {
            'from': from_email, 'account': account['email'],
        })
        _update_lead_status(from_email, 'interested')

    elif intent == 'ASKS_IDENTITY':
        reply_html = groq_reply or _tmpl_asks_identity(my_name, gp)
        _log_audit('ASKS_IDENTITY', {
            'from': from_email, 'reasoning': reasoning, 'account': account['email'],
        })

    elif intent == 'ACKNOWLEDGMENT_ONLY':
        # Pattern Interrupt: re-engage with curiosity question instead of staying silent
        reply_html = groq_reply or _tmpl_acknowledgment_only(my_name, gp)
        _log_audit('ACKNOWLEDGMENT_ONLY', {
            'from': from_email, 'reasoning': reasoning, 'account': account['email'],
        })

    elif intent == 'ASKS_PRICE':
        reply_html = groq_reply or _tmpl_asks_price(my_name, gp)

    elif intent == 'ASKS_DETAILS':
        reply_html = groq_reply or _tmpl_asks_details(my_name, gp)

    elif intent == 'PASS_UNSUB':
        reply_html = groq_reply or _tmpl_pass_unsub()
        _handle_unsub(from_email)
        _log_audit('UNSUBSCRIBED', {'email': from_email})

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

    elif intent == 'NEGATIVE_OBJECTION':
        reply_html = groq_reply or _tmpl_negative_objection()
        _handle_unsub(from_email)
        _log_audit('NEGATIVE_OBJECTION', {
            'from': from_email, 'reasoning': reasoning, 'account': account['email'],
        })

    else:
        reply_html = groq_reply or _tmpl_unknown(my_name, gp)
        create_ops_ticket(from_email, subject, body_text, intent)
        _create_human_review_ticket(from_email, subject, body_text, intent, reasoning)
        _log_audit('OPS_TICKET_CREATED', {'from': from_email, 'intent': intent})

    # ── Step 7: Enqueue reply ────────────────────────────────
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
    _update_lead_state(lead['id'], intent, product_introduced=pitched, belief_variant=variant_tag)

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
    Shared logic for analyzing a reply, assigning A/B test variants,
    and generating the response. Used by both Gmail and IMAP paths.
    """
    gp = get_generation_params()

    conversation_state = {
        "reply_count": lead.get("reply_count", 0),
        "product_introduced": lead.get("product_introduced", False),
        "last_intent": lead.get("last_intent")
    }

    # ── Step 1: Groq analyze (Phase 1: Intent classification) ─────────────────
    print(f"  [{from_email}] calling Groq analyze ({channel}) …")
    groq_result = _groq_analyze_reply(
        body_text, property_address=property_address, my_name=my_name,
        conversation_state=conversation_state, gen_params=gp
    )

    # ── Step 2: Final intent ──────────────────────────────────────────────────
    intent        = classify_intent(body_text, groq_result)
    belief_signal = (groq_result or {}).get("belief_signal", "BELIEF_UNKNOWN")
    reasoning     = groq_result.get('reasoning', '') if groq_result else ''
    confidence    = 0.9 if groq_result else 0.5
    print(f"  [{from_email}] intent={intent} belief_signal={belief_signal}")

    # ── Step 3: Variant Assignment ───────────────────────────────────────────
    variant_tag = lead.get("belief_variant")
    chosen_question = None
    if intent == "AGENT_HANDLES":
        if not variant_tag:
            variant_tag = "group_b_belief_question" if random.random() < BELIEF_QUESTION_RATE else "group_a_observation"
            print(f"  [{from_email}] Assigned new variant: {variant_tag}")
        else:
            print(f"  [{from_email}] Using existing variant: {variant_tag}")

        if variant_tag == "group_b_belief_question":
            chosen_question = random.choice(BELIEF_QUESTIONS)

    # ── Step 4: Re-run Groq with variant instructions (if AGENT_HANDLES) ──────
    if intent == "AGENT_HANDLES" and variant_tag:
        print(f"  [{from_email}] Re-calling Groq with variant instructions …")
        groq_result = _groq_analyze_reply(
            body_text, property_address=property_address, my_name=my_name,
            conversation_state=conversation_state, gen_params=gp,
            variant_tag=variant_tag, chosen_question=chosen_question
        )

    # ── Step 5: Decision Logging ──────────────────────────────────────────────
    metadata = groq_result or {}
    metadata.update({
        "variant_tag":     variant_tag,
        "belief_signal":   belief_signal,
        "intent":          intent,
        "lead_id":         lead['id'],
        "thread_id":       thread_id,
        "msg_id":          msg_id,
        "channel":         channel
    })

    _log_agent_decision(
        from_email=from_email, intent=intent, confidence=confidence,
        reasoning=reasoning, metadata=metadata,
    )

    return {
        "intent": intent,
        "belief_signal": belief_signal,
        "reasoning": reasoning,
        "variant_tag": variant_tag,
        "chosen_question": chosen_question,
        "groq_result": groq_result,
        "gp": gp
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

    intent          = analysis['intent']
    reasoning       = analysis['reasoning']
    variant_tag     = analysis['variant_tag']
    chosen_question = analysis['chosen_question']
    groq_result     = analysis['groq_result']
    gp              = analysis['gp']

    _log_audit('REPLY_RECEIVED', {
        "from":         from_email,
        "subject":      subject,
        "intent":       intent,
        "reasoning":    reasoning,
        "raw_snippet":  body_text[:300],
        "gmail_msg_id": gmail_msg_id,
        "account":      account['email'],
    })

    # ── Step 6: Choose reply ───────────────────────────────────────────────────
    # Prefer Groq's generated reply when available; fall back to static templates.
    groq_reply   = (groq_result or {}).get("reply_html", "").strip()
    reply_html: str | None = None

    # ── HIGH_NUANCE Intents: LLM reply ONLY — no template fallback ─────────────
    if intent in HIGH_NUANCE_INTENTS:
        # These require high-nuance mirroring that must come solely from the LLM
        if not groq_reply:
            # If LLM failed, fall back to a minimal safe response
            groq_reply = _tmpl_unknown(my_name, gp)
        reply_html = groq_reply
        _log_audit(f'HIGH_NUANCE_{intent}', {
            "from":             from_email,
            "account":          account['email'],
            "lead_psychology":  groq_result.get('lead_psychology', '') if groq_result else '',
        })
        _update_lead_status(from_email, intent.lower())

    elif intent == 'AGENT_HANDLES':
        reply_html = groq_reply or _tmpl_agent_handles(my_name, gp, variant_tag=variant_tag, chosen_question=chosen_question)
        _log_audit('AGENT_HANDLES', {
            "from":    from_email,
            "account": account['email'],
        })
        _update_lead_status(from_email, 'agent_handles')

    elif intent == 'NOBODY_HANDLES':
        reply_html = groq_reply or _tmpl_nobody_handles(my_name, gp)
        _log_audit('NOBODY_HANDLES', {
            "from":    from_email,
            "account": account['email'],
        })
        _update_lead_status(from_email, 'nobody_handles')

    elif intent == 'ASSISTANT_HANDLES':
        reply_html = groq_reply or _tmpl_assistant_handles(my_name, gp)
        _log_audit('ASSISTANT_HANDLES', {
            "from":    from_email,
            "account": account["email"],
        })
        _update_lead_status(from_email, 'assistant_handles')

    elif intent == 'INTERESTED':
        reply_html = groq_reply or _tmpl_interested(my_name, gp)
        _log_audit('INTERESTED', {
            "from":    from_email,
            "account": account["email"],
        })
        _update_lead_status(from_email, 'interested')

    elif intent == 'ASKS_IDENTITY':
        # They want to know who sent this — confirm identity confidently, no apology
        reply_html = groq_reply or _tmpl_asks_identity(my_name, gp)
        _log_audit('ASKS_IDENTITY', {
            "from":      from_email,
            "reasoning": reasoning,
            "account":   account['email'],
        })

    elif intent == 'ACKNOWLEDGMENT_ONLY':
        # Pattern Interrupt: re-engage with curiosity question instead of staying silent
        reply_html = groq_reply or _tmpl_acknowledgment_only(my_name, gp)
        _log_audit('ACKNOWLEDGMENT_ONLY', {
            "from":      from_email,
            "reasoning": reasoning,
            "account":   account['email'],
        })

    elif intent == 'ASKS_PRICE':
        reply_html = groq_reply or _tmpl_asks_price(my_name, gp)

    elif intent == 'ASKS_DETAILS':
        reply_html = groq_reply or _tmpl_asks_details(my_name, gp)

    elif intent == 'PASS_UNSUB':
        reply_html = groq_reply or _tmpl_pass_unsub()
        _handle_unsub(from_email)
        _log_audit('UNSUBSCRIBED', {"email": from_email})

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
        reply_html = groq_reply or _tmpl_unknown(my_name, gp)
        create_ops_ticket(from_email, subject, body_text, intent)
        _create_human_review_ticket(from_email, subject, body_text, intent, reasoning)
        _log_audit('OPS_TICKET_CREATED', {"from": from_email, "intent": intent})

    # ── Step 7: Enqueue reply ─────────────────────────────────────────────────────
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
            references=orig_msg_id # Gmail handles this via thread_id/in_reply_to mostly
        )
        auto_reply_sent = True # Marked as "sent" in terms of processed_replies because it's enqueued

    # Determine if product was introduced in this reply
    pitched = (intent in ['INTERESTED', 'ASKS_PRICE', 'ASKS_DETAILS']) or (lead.get('product_introduced', False))

    _update_lead_state(lead['id'], intent, product_introduced=pitched, belief_variant=variant_tag)

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
