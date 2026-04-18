# app.py  –  Gmail API OAuth 2.0 edition
#
# REQUIRED ENV VARS (add these – others stay the same):
#   GOOGLE_CLIENT_ID       from Google Cloud Console
#   GOOGLE_CLIENT_SECRET   from Google Cloud Console
#   GOOGLE_REDIRECT_URI    e.g. https://yourdomain.com/auth/gmail/callback
#   FLASK_SECRET_KEY       any long random string (for session signing)
#
# REQUIRED pip packages (add to requirements.txt):
#   requests  (already present)
#   flask-session  (optional – standard flask sessions work fine here)
#
# SUPABASE TABLE NEEDED (run once):
#   CREATE TABLE gmail_accounts (
#     id                      SERIAL PRIMARY KEY,
#     email                   TEXT UNIQUE NOT NULL,
#     display_name            TEXT,
#     encrypted_refresh_token TEXT NOT NULL,
#     gmail_connected         BOOLEAN DEFAULT TRUE,
#     created_at              TIMESTAMPTZ DEFAULT NOW()
#   );
#
#   -- Also add gmail_account column to lead_campaign_accounts:
#   ALTER TABLE lead_campaign_accounts
#     ADD COLUMN IF NOT EXISTS gmail_account TEXT;

import os
import base64
import json
import traceback
import secrets
import csv
import io
import re
import random
import smtplib
import imaplib
import requests
import urllib.parse
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText as _MIMEText
from datetime import datetime, timedelta, timezone, date
from flask import (Flask, request, redirect, render_template,
                   jsonify, current_app, url_for)
from flask_cors import CORS
from dotenv import load_dotenv
from supabase import create_client
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from email_validator import validate_email, EmailNotValidError
from notify import notify  # ← ntfy.sh push notifications

load_dotenv()

# ── Supabase ──────────────────────────────────────────────────────────────────
SUPABASE_URL = os.environ['SUPABASE_URL']
SUPABASE_KEY = os.environ['SUPABASE_SERVICE_ROLE_KEY']
supabase     = create_client(SUPABASE_URL, SUPABASE_KEY)

# ── Encryption ────────────────────────────────────────────────────────────────
ENCRYPTION_KEY = bytes.fromhex(os.environ['ENCRYPTION_KEY'])

def aesgcm_encrypt(plaintext: str) -> str:
    aesgcm = AESGCM(ENCRYPTION_KEY)
    nonce  = secrets.token_bytes(12)
    ct     = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    return base64.b64encode(nonce + ct).decode('utf-8')

def aesgcm_decrypt(b64text: str) -> str:
    data   = base64.b64decode(b64text)
    nonce  = data[:12]
    ct     = data[12:]
    return AESGCM(ENCRYPTION_KEY).decrypt(nonce, ct, None).decode('utf-8')


# ── Spintax ───────────────────────────────────────────────────────────────────
def process_spintax(text: str) -> str:
    pattern = re.compile(r'\{\{([^{}]+?)\}\}')
    while True:
        m = pattern.search(text)
        if not m:
            break
        text = text[:m.start()] + random.choice(m.group(1).split('|')) + text[m.end():]
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


# ── CSV field parsers ─────────────────────────────────────────────────────────

def _parse_last_12m_sales(raw: str) -> str:
    """
    Extract the sold count (first integer) from MLS export values like:
      "39"            →  "39"
      "(39, 7, 42)"   →  "39"   (Sold / Pending / Expired — use Sold only)
      "39 sold"       →  "39"
    Returns empty string if no integer found.
    """
    if not raw:
        return ""
    m = re.search(r'\d+', raw.strip())
    return m.group(0) if m else ""


def _parse_active_listings(raw: str) -> str:
    """
    Extract the first bracketed integer from MLS export values like:
      "For Sale (3)"                               →  "3"
      "For Sale (1), For Sale (8), For Sale (2)"   →  "1"  (first entry only)
      "5"                                          →  "5"  (plain number fallback)
    Returns empty string if nothing found.
    """
    if not raw:
        return ""
    # Primary: parenthesised number  e.g.  "For Sale (1)"
    m = re.search(r'\((\d+)\)', raw)
    if m:
        return m.group(1)
    # Fallback: any plain integer in the string
    m = re.search(r'\d+', raw.strip())
    return m.group(0) if m else ""


# ── Gmail OAuth constants ─────────────────────────────────────────────────────
GOOGLE_CLIENT_ID      = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET  = os.environ.get('GOOGLE_CLIENT_SECRET', '')
GOOGLE_REDIRECT_URI   = os.environ.get('GOOGLE_REDIRECT_URI', '')
GOOGLE_AUTH_URL       = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL      = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL   = "https://www.googleapis.com/oauth2/v3/userinfo"
GOOGLE_REVOKE_URL     = "https://oauth2.googleapis.com/revoke"

# Scopes: send mail + read profile email address
GMAIL_SCOPES = [
         "https://www.googleapis.com/auth/gmail.send",
         "https://www.googleapis.com/auth/gmail.readonly",
         "https://www.googleapis.com/auth/userinfo.email",
         "https://www.googleapis.com/auth/userinfo.profile",
     ]


# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__, template_folder="templates")

CORS(app, resources={
    r"/api/*": {
        "origins": ["replyzeai.com", "replyzeai.com/demooff"],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "Origin"]
    }
})


# ── Pages ─────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('admin.html')

@app.route('/admin')
def admin():
    return render_template('admin.html')


# ── Stateless OAuth state helpers ────────────────────────────────────────────
import hmac
import hashlib
import time

def _make_oauth_state() -> str:
    nonce     = secrets.token_urlsafe(24)
    ts        = str(int(time.time()))
    payload   = f"{nonce}.{ts}"
    sig       = hmac.new(ENCRYPTION_KEY[:32], payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"

def _verify_oauth_state(state: str, max_age: int = 600) -> bool:
    try:
        parts = state.rsplit('.', 1)
        if len(parts) != 2:
            return False
        payload, sig = parts
        expected = hmac.new(ENCRYPTION_KEY[:32], payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        _, ts = payload.split('.', 1)
        if int(time.time()) - int(ts) > max_age:
            return False
        return True
    except Exception:
        return False


@app.route('/auth/gmail')
def auth_gmail():
    if not GOOGLE_CLIENT_ID:
        return "GOOGLE_CLIENT_ID not configured", 500

    state = _make_oauth_state()

    params = {
        "client_id":     GOOGLE_CLIENT_ID,
        "redirect_uri":  GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope":         " ".join(GMAIL_SCOPES),
        "access_type":   "offline",
        "prompt":        "consent",
        "state":         state,
    }
    auth_url = GOOGLE_AUTH_URL + "?" + urllib.parse.urlencode(params)
    return redirect(auth_url)


@app.route('/auth/gmail/callback')
def auth_gmail_callback():
    returned_state = request.args.get('state', '')
    if not returned_state or not _verify_oauth_state(returned_state):
        return "OAuth state invalid or expired. Please try connecting again.", 400

    error = request.args.get('error')
    if error:
        return redirect(f"/admin?oauth_error={urllib.parse.quote(error)}")

    code = request.args.get('code')
    if not code:
        return "Missing auth code from Google.", 400

    token_resp = requests.post(GOOGLE_TOKEN_URL, data={
        "code":          code,
        "client_id":     GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri":  GOOGLE_REDIRECT_URI,
        "grant_type":    "authorization_code",
    }, timeout=15)

    if token_resp.status_code != 200:
        return (f"Token exchange failed: {token_resp.status_code} "
                f"{token_resp.text}"), 400

    tokens        = token_resp.json()
    access_token  = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")

    if not refresh_token:
        return ("No refresh_token returned. "
                "Please revoke app access in your Google account and try again."), 400

    info_resp = requests.get(
        GOOGLE_USERINFO_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    if info_resp.status_code != 200:
        return "Could not fetch user info from Google.", 400

    info         = info_resp.json()
    email        = info.get("email", "").lower()
    display_name = info.get("name") or email

    if not email:
        return "Could not determine Gmail address.", 400

    encrypted_rt = aesgcm_encrypt(refresh_token)

    supabase.table("gmail_accounts").upsert({
        "email":                   email,
        "display_name":            display_name,
        "encrypted_refresh_token": encrypted_rt,
        "gmail_connected":         True,
    }, on_conflict="email").execute()

    return redirect("https://www.replyzeai.com/goods/admin?oauth_success=1")


# ── Gmail accounts API ────────────────────────────────────────────────────────

@app.route('/api/gmail-accounts', methods=['GET'])
def api_get_gmail_accounts():
    try:
        accounts = supabase.table("gmail_accounts").select(
            "id, email, display_name, gmail_connected, created_at"
        ).order("created_at").execute()
        return jsonify({"ok": True, "accounts": accounts.data}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/gmail-accounts/<int:account_id>', methods=['DELETE'])
def api_delete_gmail_account(account_id):
    try:
        acct = supabase.table("gmail_accounts") \
            .select("encrypted_refresh_token, email") \
            .eq("id", account_id) \
            .single() \
            .execute()

        if not acct.data:
            return jsonify({"error": "Account not found"}), 404

        try:
            rt = aesgcm_decrypt(acct.data["encrypted_refresh_token"])
            requests.post(GOOGLE_REVOKE_URL, params={"token": rt}, timeout=10)
        except Exception:
            pass

        supabase.table("gmail_accounts").delete().eq("id", account_id).execute()
        return jsonify({"ok": True}), 200

    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/gmail-accounts/<int:account_id>/test', methods=['POST'])
def api_test_gmail_account(account_id):
    try:
        acct = supabase.table("gmail_accounts") \
            .select("*").eq("id", account_id).single().execute()

        if not acct.data:
            return jsonify({"error": "Account not found"}), 404

        account = acct.data

        token_resp = requests.post(GOOGLE_TOKEN_URL, data={
            "client_id":     GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "refresh_token": aesgcm_decrypt(account["encrypted_refresh_token"]),
            "grant_type":    "refresh_token",
        }, timeout=15)

        if token_resp.status_code != 200:
            return jsonify({
                "error": "token_refresh_failed",
                "detail": token_resp.text
            }), 400

        access_token = token_resp.json().get("access_token")

        from email.mime.text import MIMEText
        msg            = MIMEText("<p>ReplyzeAI Gmail API test — connection is working!</p>", "html", "utf-8")
        msg["To"]      = account["email"]
        msg["From"]    = f"{account['display_name']} <{account['email']}>"
        msg["Subject"] = "[ReplyzeAI] Connection test"

        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8").rstrip("=")

        send_resp = requests.post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            headers={"Authorization": f"Bearer {access_token}",
                     "Content-Type": "application/json"},
            json={"raw": raw},
            timeout=30,
        )

        if send_resp.status_code in (200, 201):
            return jsonify({"ok": True, "message": "Test email sent to " + account["email"]}), 200

        return jsonify({
            "error": "send_failed",
            "detail": send_resp.text
        }), 400

    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ── Account status ────────────────────────────────────────────────────────────
@app.route('/api/account-status', methods=['GET'])
def api_get_account_status():
    try:
        DAILY_LIMIT = int(os.environ.get('GMAIL_DAILY_LIMIT', 500))
        today       = date.today().isoformat()
        accounts    = supabase.table("gmail_accounts").select("*").execute()

        statuses = []
        for acct in accounts.data:
            cd = supabase.table("daily_email_counts") \
                .select("count") \
                .eq("email_account", acct["email"]) \
                .eq("date", today) \
                .execute()

            count = cd.data[0]["count"] if cd.data else 0
            statuses.append({
                "email":          acct["email"],
                "display_name":   acct["display_name"],
                "gmail_connected": acct["gmail_connected"],
                "sent_today":     count,
                "remaining_today": DAILY_LIMIT - count,
                "daily_limit":    DAILY_LIMIT,
            })

        return jsonify({"ok": True, "accounts": statuses}), 200

    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ── SMTP / IMAP accounts — list ───────────────────────────────────────────────

@app.route('/api/smtp-accounts', methods=['GET'])
def api_get_smtp_accounts():
    try:
        rows = supabase.table("smtp_accounts") \
            .select("id, email, display_name, smtp_host, smtp_port, smtp_username, imap_host, imap_port, created_at") \
            .order("created_at") \
            .execute()
        return jsonify({"ok": True, "accounts": rows.data}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ── SMTP / IMAP accounts — add ────────────────────────────────────────────────

@app.route('/api/smtp-accounts', methods=['POST'])
def api_add_smtp_account():
    """
    Save SMTP credentials encrypted. Does NOT run a live connection test on
    save — call /test explicitly after saving. This prevents hosting firewalls
    from blocking the outbound SMTP port and causing false 500 errors.
    """
    try:
        body = request.get_json(force=True) or {}

        email         = (body.get("email") or "").strip().lower()
        display_name  = (body.get("display_name") or "").strip() or email
        smtp_host     = (body.get("smtp_host") or "").strip()
        smtp_port_raw = body.get("smtp_port")
        smtp_port     = int(smtp_port_raw) if smtp_port_raw else 587
        smtp_username = (body.get("smtp_username") or "").strip()
        smtp_password = (body.get("smtp_password") or "")
        imap_host     = (body.get("imap_host") or "").strip() or None
        imap_port_raw = body.get("imap_port")
        imap_port     = int(imap_port_raw) if (imap_host and imap_port_raw) else (993 if imap_host else None)

        if not email or not smtp_host or not smtp_username or not smtp_password:
            return jsonify({
                "error": "missing_fields",
                "detail": "email, smtp_host, smtp_username and smtp_password are all required"
            }), 400

        try:
            validate_email(email, check_deliverability=False)
        except EmailNotValidError as ve:
            return jsonify({"error": "invalid_email", "detail": str(ve)}), 400

        encrypted_pw = aesgcm_encrypt(smtp_password)

        supabase.table("smtp_accounts").upsert({
            "email":                    email,
            "display_name":             display_name,
            "smtp_host":                smtp_host,
            "smtp_port":                smtp_port,
            "smtp_username":            smtp_username,
            "encrypted_smtp_password":  encrypted_pw,
            "imap_host":                imap_host,
            "imap_port":                imap_port,
        }, on_conflict="email").execute()

        return jsonify({"ok": True, "test_ok": None,
                        "message": "Account saved. Click Test to verify the connection."}), 200

    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ── SMTP / IMAP accounts — delete ─────────────────────────────────────────────

@app.route('/api/smtp-accounts/<int:account_id>', methods=['DELETE'])
def api_delete_smtp_account(account_id):
    try:
        acct = supabase.table("smtp_accounts") \
            .select("id, email").eq("id", account_id).single().execute()
        if not acct.data:
            return jsonify({"error": "not_found"}), 404
        supabase.table("smtp_accounts").delete().eq("id", account_id).execute()
        return jsonify({"ok": True}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ── SMTP / IMAP accounts — test ───────────────────────────────────────────────

@app.route('/api/smtp-accounts/<int:account_id>/test', methods=['POST'])
def api_test_smtp_account(account_id):
    """
    Test SMTP credentials by sending a real email via plain SMTP (smtplib).
    Works for all providers including smtp2go — always uses the SMTP protocol,
    never the smtp2go HTTP REST API.
    """
    try:
        acct = supabase.table("smtp_accounts") \
            .select("*").eq("id", account_id).single().execute()
        if not acct.data:
            return jsonify({"error": "not_found"}), 404

        a        = acct.data
        password = aesgcm_decrypt(a["encrypted_smtp_password"])
        port     = int(a.get("smtp_port") or 587)

        # ── plain SMTP socket (works for all providers incl. smtp2go) ────
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = "[ReplyzeAI] SMTP connection test"
            msg["From"]    = "{} <{}>".format(a["display_name"], a["email"])
            msg["To"]      = a["email"]
            msg.attach(_MIMEText(
                "<p>&#x2705; <strong>ReplyzeAI SMTP test passed!</strong><br>"
                "Account <code>{}</code> is connected and sending correctly.</p>".format(a["email"]),
                "html", "utf-8"
            ))

            if port == 465:
                server = smtplib.SMTP_SSL(a["smtp_host"], port, timeout=20)
            else:
                server = smtplib.SMTP(a["smtp_host"], port, timeout=20)
                server.ehlo()
                server.starttls()
                server.ehlo()

            server.login(a["smtp_username"], password)
            server.sendmail(a["email"], [a["email"]], msg.as_string())
            server.quit()
            return jsonify({"ok": True,
                            "message": "Test email sent to {}".format(a["email"])}), 200

        except smtplib.SMTPAuthenticationError as auth_err:
            return jsonify({"error": "auth_failed",
                            "detail": "Wrong username or password — {}".format(str(auth_err))}), 400
        except (smtplib.SMTPConnectError, ConnectionRefusedError, OSError) as conn_err:
            return jsonify({
                "error": "connection_failed",
                "detail": (
                    "Cannot reach {}:{} from this server — your hosting platform likely blocks "
                    "outbound SMTP ports (587/465). This is normal. Your worker.py running on "
                    "GitHub Actions is NOT affected and will send fine. "
                    "Raw error: {}".format(a["smtp_host"], port, str(conn_err))
                )
            }), 400
        except smtplib.SMTPException as smtp_err:
            return jsonify({"error": "smtp_error", "detail": str(smtp_err)}), 400

    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ── SMTP send helper (use in worker.py) ──────────────────────────────────────

def send_via_smtp(smtp_acct, to_email, subject, html_body, from_name=None):
    """
    Send one email via SMTP. smtp_acct must be a row dict from smtp_accounts.
    Raises smtplib exceptions on failure — caller should catch and log.
    Compatible with Python 3.8+.
    """
    password    = aesgcm_decrypt(smtp_acct["encrypted_smtp_password"])
    sender_name = from_name or smtp_acct.get("display_name") or smtp_acct["email"]

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = "{} <{}>".format(sender_name, smtp_acct["email"])
    msg["To"]      = to_email
    msg.attach(_MIMEText(html_body, "html", "utf-8"))

    port = int(smtp_acct.get("smtp_port") or 587)
    if port == 465:
        server = smtplib.SMTP_SSL(smtp_acct["smtp_host"], port, timeout=30)
    else:
        server = smtplib.SMTP(smtp_acct["smtp_host"], port, timeout=30)
        server.ehlo()
        server.starttls()
        server.ehlo()

    server.login(smtp_acct["smtp_username"], password)
    server.sendmail(smtp_acct["email"], [to_email], msg.as_string())
    server.quit()


# ── Campaigns ─────────────────────────────────────────────────────────────────
@app.route('/api/campaigns', methods=['GET'])
def api_get_campaigns():
    try:
        campaigns = supabase.table("campaigns") \
            .select("*").order("created_at", desc=True).execute()
        return jsonify({"ok": True, "campaigns": campaigns.data}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/campaigns/<int:campaign_id>/stats', methods=['GET'])
def api_campaign_stats(campaign_id):
    """Aggregate delivery, engagement and reply stats for a single campaign."""
    try:
        # ── Campaign + follow-ups ─────────────────────────────────────────
        campaign_res = supabase.table("campaigns") \
            .select("*").eq("id", campaign_id).single().execute()
        if not campaign_res.data:
            return jsonify({"error": "not_found"}), 404

        followups_res = supabase.table("campaign_followups") \
            .select("*").eq("campaign_id", campaign_id) \
            .order("sequence").execute()

        # ── Email queue ───────────────────────────────────────────────────
        queue_res = supabase.table("email_queue") \
            .select("id,sequence,sent_at,scheduled_for,lead_email,sent_from") \
            .eq("campaign_id", campaign_id).execute()
        queue = queue_res.data or []

        total_queued  = len(queue)
        total_sent    = sum(1 for e in queue if e.get('sent_at'))
        total_pending = sum(1 for e in queue if not e.get('sent_at'))

        # Per-sequence breakdown
        by_seq = {}
        for e in queue:
            seq = e.get('sequence', 0)
            if seq not in by_seq:
                by_seq[seq] = {'queued': 0, 'sent': 0}
            by_seq[seq]['queued'] += 1
            if e.get('sent_at'):
                by_seq[seq]['sent'] += 1

        # Unique leads & sending accounts
        unique_leads    = len(set(e['lead_email'] for e in queue if e.get('lead_email')))
        sending_accounts = list(set(e['sent_from'] for e in queue if e.get('sent_from')))

        # First / last send timestamps
        sent_times = [e['sent_at'] for e in queue if e.get('sent_at')]
        first_sent = min(sent_times) if sent_times else None
        last_sent  = max(sent_times) if sent_times else None

        # ── Link clicks ───────────────────────────────────────────────────
        clicks_res = supabase.table("link_clicks") \
            .select("id,lead_id,clicked_at,action_type") \
            .eq("campaign_id", campaign_id).execute()
        clicks = clicks_res.data or []
        total_clicks    = len(clicks)
        unique_clickers = len(set(c['lead_id'] for c in clicks if c.get('lead_id')))

        # ── Lead activity (responses tied to campaign) ────────────────────
        activity_res = supabase.table("lead_activity") \
            .select("id,action_type") \
            .eq("campaign_id", campaign_id).execute()
        activity    = activity_res.data or []
        total_responses = sum(1 for a in activity if a.get('action_type') == 'responded')

        return jsonify({
            "ok": True,
            "campaign":   campaign_res.data,
            "follow_ups": followups_res.data or [],
            "stats": {
                "total_queued":      total_queued,
                "total_sent":        total_sent,
                "total_pending":     total_pending,
                "unique_leads":      unique_leads,
                "total_clicks":      total_clicks,
                "unique_clickers":   unique_clickers,
                "total_responses":   total_responses,
                "first_sent":        first_sent,
                "last_sent":         last_sent,
                "sending_accounts":  sending_accounts,
                "by_sequence":       by_seq,
            }
        }), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/campaigns/<int:campaign_id>/diagnose', methods=['POST'])
def api_campaign_diagnose(campaign_id):
    """
    Pulls all campaign context from Supabase, then calls Groq to produce
    an AI diagnosis. GROQ_API_KEY is read from the environment — never
    exposed to the frontend.
    """
    groq_key = os.environ.get('GROQ_API_KEY', '')
    if not groq_key:
        return jsonify({"error": "GROQ_API_KEY not configured on server"}), 500

    try:
        # ── Campaign + follow-ups ────────────────────────────────────────
        campaign_res = supabase.table("campaigns") \
            .select("*").eq("id", campaign_id).single().execute()
        if not campaign_res.data:
            return jsonify({"error": "not_found"}), 404
        campaign = campaign_res.data

        followups_res = supabase.table("campaign_followups") \
            .select("*").eq("campaign_id", campaign_id) \
            .order("sequence").execute()
        follow_ups = followups_res.data or []

        # ── Queue stats ──────────────────────────────────────────────────
        queue_res = supabase.table("email_queue") \
            .select("id,sequence,sent_at,scheduled_for,lead_email,sent_from") \
            .eq("campaign_id", campaign_id).execute()
        queue = queue_res.data or []

        total_queued   = len(queue)
        total_sent     = sum(1 for e in queue if e.get('sent_at'))
        total_pending  = sum(1 for e in queue if not e.get('sent_at'))
        unique_leads   = len(set(e['lead_email'] for e in queue if e.get('lead_email')))
        sending_accounts = list(set(e['sent_from'] for e in queue if e.get('sent_from')))
        sent_times     = [e['sent_at'] for e in queue if e.get('sent_at')]
        first_sent     = min(sent_times) if sent_times else None
        last_sent      = max(sent_times) if sent_times else None

        by_seq = {}
        for e in queue:
            seq = e.get('sequence', 0)
            if seq not in by_seq:
                by_seq[seq] = {'queued': 0, 'sent': 0}
            by_seq[seq]['queued'] += 1
            if e.get('sent_at'):
                by_seq[seq]['sent'] += 1

        # ── Clicks ───────────────────────────────────────────────────────
        clicks_res = supabase.table("link_clicks") \
            .select("id,lead_id,clicked_at") \
            .eq("campaign_id", campaign_id).execute()
        clicks          = clicks_res.data or []
        total_clicks    = len(clicks)
        unique_clickers = len(set(c['lead_id'] for c in clicks if c.get('lead_id')))

        # ── Replies from lead_activity ───────────────────────────────────
        activity_res = supabase.table("lead_activity") \
            .select("id,action_type") \
            .eq("campaign_id", campaign_id).execute()
        activity        = activity_res.data or []
        total_responses = sum(1 for a in activity if a.get('action_type') == 'responded')

        # ── Historical reply rate for this list ──────────────────────────
        list_leads_res = supabase.table("leads") \
            .select("id,responded") \
            .eq("list_name", campaign['list_name']).execute()
        list_leads     = list_leads_res.data or []
        list_total     = len(list_leads)
        list_responded = sum(1 for l in list_leads if l.get('responded'))

        # ── Sending account daily usage ──────────────────────────────────
        account_usage = []
        for acct in sending_accounts[:5]:  # cap to avoid too many queries
            today = datetime.now(timezone.utc).date().isoformat()
            usage_res = supabase.table("daily_email_counts") \
                .select("count,date") \
                .eq("email_account", acct) \
                .order("date", desc=True).limit(7).execute()
            account_usage.append({
                "account": acct,
                "recent_days": usage_res.data or []
            })

        # ── Does the body contain any links? ────────────────────────────
        body_text      = campaign.get('body', '')
        has_links      = bool(re.search(r'https?://', body_text))
        link_count     = len(re.findall(r'https?://\S+', body_text))

        # ── Does subject look spammy? (basic heuristics) ────────────────
        subject        = campaign.get('subject', '')
        spam_words     = ['free','guarantee','no risk','limited time','act now',
                          'click here','winner','congratulations','urgent']
        subject_flags  = [w for w in spam_words if w.lower() in subject.lower()]
        all_caps_words = len(re.findall(r'\b[A-Z]{3,}\b', subject))

        # ── Build prompt ─────────────────────────────────────────────────
        send_rate  = round(total_sent / total_queued * 100, 1) if total_queued else 0
        click_rate = round(unique_clickers / total_sent * 100, 2) if total_sent else 0
        reply_rate = round(total_responses / total_sent * 100, 2) if total_sent else 0
        hist_rate  = round(list_responded / list_total * 100, 2) if list_total else 0

        seq_lines = '\n'.join(
            f"  Seq {'Initial' if k == 0 else '#'+str(k)}: "
            f"{v['sent']}/{v['queued']} sent "
            f"({round(v['sent']/v['queued']*100,1) if v['queued'] else 0}%)"
            for k, v in sorted(by_seq.items())
        )

        account_lines = ''
        for au in account_usage:
            days = ', '.join(f"{d['date']}:{d['count']}" for d in au['recent_days'][:3])
            account_lines += f"  {au['account']}: {days or 'no data'}\n"

        # ── Compute send window duration ─────────────────────────────────
        send_window_minutes = None
        if first_sent and last_sent:
            try:
                fmt = '%Y-%m-%dT%H:%M:%S'
                t1 = datetime.fromisoformat(first_sent.replace('Z', '+00:00'))
                t2 = datetime.fromisoformat(last_sent.replace('Z', '+00:00'))
                send_window_minutes = round((t2 - t1).total_seconds() / 60, 1)
            except Exception:
                pass

        prompt = f"""You are a senior cold email strategist who diagnoses campaign failures at the architectural level — not just the symptom level.

Your job is to identify the ROOT CAUSE chain: why did this campaign structurally fail, and how do the individual problems compound each other? Do not produce a checklist of isolated issues. Connect the dots.

═══ CAMPAIGN DATA ═══════════════════════════════════════════════
Name:         {campaign['name']}
Lead list:    {campaign['list_name']}
Subject line: {subject}
Body:
{body_text[:800]}{'...[truncated]' if len(body_text) > 800 else ''}

Follow-ups configured: {len(follow_ups)}
{chr(10).join(f"  Follow-up #{f['sequence']}: +{f['days_after_previous']}d — subject: {f['subject']}" for f in follow_ups) if follow_ups else '  (none — single-shot campaign)'}
Send delay: {campaign.get('send_delay_seconds', 0)}s ± {campaign.get('send_jitter_seconds', 0)}s jitter

═══ DELIVERY ════════════════════════════════════════════════════
Total sent:    {total_sent} of {total_queued} queued ({send_rate}% server-acceptance rate)
Send window:   {f'{send_window_minutes} minutes total ({round(total_sent/send_window_minutes,1) if send_window_minutes and send_window_minutes > 0 else "?"} emails/min)' if send_window_minutes is not None else 'unknown'}
First sent:    {first_sent or 'N/A'}
Last sent:     {last_sent or 'N/A'}
Sending accounts: {', '.join(sending_accounts) or 'unknown'}
Daily usage (last 3 days per account):
{account_lines.strip() or '  (no data)'}

Sequence breakdown:
{seq_lines or '  (no data)'}

═══ ENGAGEMENT ══════════════════════════════════════════════════
Links in body: {'YES — ' + str(link_count) + ' link(s) found' if has_links else 'NO — omit CTR from analysis entirely'}
Clicks:        {total_clicks} ({unique_clickers} unique)
Replies:       {total_responses} ({reply_rate}% reply rate)

═══ LIST HEALTH ═════════════════════════════════════════════════
Leads in list:        {list_total}
Previously responded: {list_responded} ({hist_rate}% historical reply rate on this list across ALL campaigns)

═══ SUBJECT FLAGS ═══════════════════════════════════════════════
Spam-trigger words: {', '.join(subject_flags) if subject_flags else 'none detected'}
ALL-CAPS words:     {all_caps_words}

═══ ANALYSIS RULES (follow strictly) ════════════════════════════
1. CONNECT PROBLEMS — don't list symptoms in isolation. Show how high velocity → spam folder → copy never seen → reply rate irrelevant is one chain, not three separate issues.
2. OFFER TRUST THRESHOLD — evaluate whether the ask in the email (what you're asking the recipient to do or agree to) is calibrated correctly for a cold first touch with zero prior relationship. A high-trust ask (e.g. handing over operational control, sharing CRM access, booking a call) needs a sequence to warm up to it. A low-trust ask (e.g. "reply yes/no") can work in one touch.
3. STRUCTURAL VERDICT — conclude whether this campaign was "winnable as configured" or "structurally unwinnable regardless of copy quality." Be direct.
4. NO FILLER — if the copy is genuinely strong, say so plainly and move on. Don't pad with generic advice.
5. If body has NO links, do not mention CTR or clicks anywhere.
6. If follow-ups = 0, explain WHY that matters specifically for THIS offer — not just "follow-ups increase reply rates."
7. Send velocity matters: anything over 2 emails/minute from a single domain is a deliverability risk. Calculate it from the send window and call it out if it's a problem.

Respond in this EXACT structure (### headers, no preamble, no intro sentence):

### 🔗 Root Cause Chain
(2–4 sentences max — the single connected narrative of why this failed, cause → effect → outcome)

### 🚨 Compounding Problems
(Bullet each issue, but show how it made the others worse — reference actual numbers)

### 📊 Benchmarks
(Only metrics that exist and matter for this campaign — skip CTR if no links)

### 🔧 Rebuild Plan
(Numbered steps to fix the architecture, not just the tactics — be specific: exact days, exact sequences, exact trust-building steps if the offer needs them)

### ✅ Keep
(What's genuinely working — be honest and brief)
"""

        # ── Call Groq ────────────────────────────────────────────────────
        groq_resp = requests.post(
            'https://api.groq.com/openai/v1/chat/completions',
            headers={
                'Authorization': f'Bearer {groq_key}',
                'Content-Type':  'application/json',
            },
            json={
                'model':      'llama-3.3-70b-versatile',
                'max_tokens': 1024,
                'messages':   [{'role': 'user', 'content': prompt}],
            },
            timeout=30,
        )
        groq_data = groq_resp.json()
        if 'error' in groq_data:
            return jsonify({"error": groq_data['error'].get('message', 'Groq error')}), 502

        diagnosis = groq_data['choices'][0]['message']['content']
        return jsonify({"ok": True, "diagnosis": diagnosis}), 200

    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/campaigns', methods=['POST'])
def api_create_campaign():
    try:
        data = request.get_json(force=True)

        result = supabase.table("campaigns").insert({
            "name":             data.get('name'),
            "subject":          data.get('subject'),
            "body":             data.get('body'),
            "list_name":        data.get('list_name'),
            "send_immediately": data.get('send_immediately', False),
        }).execute()

        if getattr(result, "error", None):
            return jsonify({"error": "db_error", "detail": str(result.error)}), 500

        campaign    = result.data[0]
        campaign_id = campaign['id']

        for i, fu in enumerate(data.get('follow_ups', [])):
            supabase.table("campaign_followups").insert({
                "campaign_id":        campaign_id,
                "subject":            fu.get('subject'),
                "body":               fu.get('body'),
                "days_after_previous": fu.get('days_after', 1),
                "sequence":           i + 1,
            }).execute()

        if data.get('send_immediately'):
            leads = supabase.table("leads") \
                .select("*").eq("list_name", data.get('list_name')).execute()

            if leads.data:
                queue = []
                for lead in leads.data:
                    queue.append({
                        "campaign_id":   campaign_id,
                        "lead_id":       lead['id'],
                        "lead_email":    lead['email'],
                        "subject":       render_email_template(data.get('subject', ''), lead),
                        "body":          render_email_template(data.get('body', ''),    lead),
                        "sequence":      0,
                        "scheduled_for": datetime.now(timezone.utc).isoformat(),
                    })

                for i in range(0, len(queue), 100):
                    supabase.table("email_queue").insert(queue[i:i+100]).execute()

                notify(
                    '📣 Campaign Queued',
                    f'"{data.get("name", "")}" → {len(leads.data)} emails queued immediately.',
                    priority='default', tags='loudspeaker',
                )

        return jsonify({"ok": True, "campaign": campaign}), 200

    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/queue-followup', methods=['POST'])
def api_queue_followup():
    try:
        data        = request.get_json(force=True)
        campaign_id = data.get('campaign_id')
        sequence    = data.get('sequence')

        if not campaign_id or sequence is None:
            return jsonify({"error": "campaign_id and sequence required"}), 400

        campaign = supabase.table("campaigns") \
            .select("*").eq("id", campaign_id).single().execute()
        follow_up = supabase.table("campaign_followups") \
            .select("*").eq("campaign_id", campaign_id).eq("sequence", sequence) \
            .single().execute()

        if not campaign.data or not follow_up.data:
            return jsonify({"error": "Campaign or follow-up not found"}), 404

        leads = supabase.table("leads") \
            .select("*").eq("list_name", campaign.data['list_name']).execute()

        if not leads.data:
            return jsonify({"ok": True, "queued": 0}), 200

        send_date = datetime.now(timezone.utc) + timedelta(
            days=follow_up.data['days_after_previous'])
        queue = []

        for lead in leads.data:
            queue.append({
                "campaign_id":   campaign_id,
                "lead_id":       lead['id'],
                "lead_email":    lead['email'],
                "subject":       render_email_template(follow_up.data['subject'], lead),
                "body":          render_email_template(follow_up.data['body'],    lead),
                "sequence":      sequence,
                "scheduled_for": send_date.isoformat(),
            })

        total = 0
        for i in range(0, len(queue), 100):
            supabase.table("email_queue").insert(queue[i:i+100]).execute()
            total += len(queue[i:i+100])

        return jsonify({"ok": True, "queued": total}), 200

    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ── Leads ─────────────────────────────────────────────────────────────────────
@app.route('/api/leads/lists', methods=['GET'])
def api_get_lead_lists():
    try:
        query = supabase.table("leads").select("list_name").execute()
        counts = {}
        for lead in query.data:
            n = lead.get('list_name', 'Unknown')
            if n:
                counts[n] = counts.get(n, 0) + 1
        return jsonify({"ok": True,
                        "lists": [{"list_name": n, "lead_count": c}
                                  for n, c in counts.items()]}), 200
    except Exception as e:
        current_app.logger.error(traceback.format_exc())
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/leads/import', methods=['POST'])
def api_import_leads():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file      = request.files['file']
        list_name = request.form.get('list_name', 'Imported List')

        if not file.filename or not file.filename.lower().endswith('.csv'):
            return jsonify({"error": "Only CSV files are supported"}), 400

        raw     = file.read()
        decoded = None
        for enc in ('utf-8-sig', 'utf-8', 'latin-1', 'windows-1252', 'iso-8859-1'):
            try:
                decoded = raw.decode(enc); break
            except UnicodeDecodeError:
                continue
        if decoded is None:
            decoded = raw.decode('latin-1')
        decoded = decoded.lstrip('\ufeff')

        reader = csv.DictReader(io.StringIO(decoded))

        if not reader.fieldnames:
            return jsonify({"error": "CSV has no headers"}), 400
        if 'email' not in [h.lower() for h in reader.fieldnames]:
            return jsonify({"error": "CSV must contain an email column"}), 400

        HEADER_ALIASES = {
            # name
            "name": "name", "first name": "name", "first_name": "name",
            "firstname": "name", "full name": "name", "full_name": "name",
            "contact name": "name", "contact_name": "name",
            # last name
            "lastname": "last name", "last_name": "last name", "surname": "last name",
            # ai hooks
            "ai hook": "ai hooks", "ai hooks": "ai hooks", "ai_hook": "ai hooks",
            # last sale
            "lastsale": "last sale", "last sale": "last sale", "last_sale": "last sale",
            # open house
            "openhouse": "open house", "open house": "open house", "open_house": "open house",
            # ── NEW: last 12 month sales (MLS export variations) ──────────────
            "last 12 m sales":     "last_12m_sales",
            "last 12m sales":      "last_12m_sales",
            "last12msales":        "last_12m_sales",
            "last 12 month sales": "last_12m_sales",
            "last12monthsales":    "last_12m_sales",
            "12m sales":           "last_12m_sales",
            "12 m sales":          "last_12m_sales",
            "last_12m_sales":      "last_12m_sales",
            # ── NEW: active listings (MLS export variations) ──────────────────
            "active listings":     "active_listings",
            "activelistings":      "active_listings",
            "active listing":      "active_listings",
            "active_listings":     "active_listings",
        }

        STANDARD_FIELDS = {
            "email", "name", "last name", "city", "brokerage",
            "service", "street", "ai hooks", "open house", "last sale",
            # NEW
            "last_12m_sales", "active_listings",
        }

        leads_by_email = {}
        for row in reader:
            if not row:
                continue
            cleaned = {}
            for k, v in row.items():
                if not k:
                    continue
                clean_k = re.sub(r'[^\x20-\x7E]', '', k).strip().lower()
                key = HEADER_ALIASES.get(clean_k, clean_k)
                cleaned[key] = v.strip() if v else ""

            email = cleaned.get("email", "").lower()
            if not email:
                continue
            try:
                validate_email(email)
            except EmailNotValidError:
                continue

            # ── Parse structured MLS fields ───────────────────────────────────
            # last_12m_sales: first integer from e.g. "(39, 7, 42)" → "39"
            raw_sales = cleaned.get("last_12m_sales", "")
            cleaned["last_12m_sales"] = _parse_last_12m_sales(raw_sales)

            # active_listings: first bracketed int from e.g. "For Sale (1)" → "1"
            raw_listings = cleaned.get("active_listings", "")
            cleaned["active_listings"] = _parse_active_listings(raw_listings)

            leads_by_email[email] = {
                "email":            email,
                "name":             cleaned.get("name", ""),
                "last_name":        cleaned.get("last name", ""),
                "city":             cleaned.get("city", ""),
                "brokerage":        cleaned.get("brokerage", ""),
                "service":          cleaned.get("service", ""),
                "street":           cleaned.get("street", ""),
                "ai_hooks":         cleaned.get("ai hooks", ""),
                "open_house":       cleaned.get("open house", ""),
                "last_sale":        cleaned.get("last sale", ""),
                # NEW parsed fields
                "last_12m_sales":   cleaned["last_12m_sales"],
                "active_listings":  cleaned["active_listings"],
                "list_name":        list_name,
                "custom_fields":    {k: v for k, v in cleaned.items()
                                     if k not in STANDARD_FIELDS},
            }

        leads = list(leads_by_email.values())
        for i in range(0, len(leads), 100):
            r = supabase.table("leads").upsert(
                leads[i:i+100], on_conflict="email").execute()
            if getattr(r, "error", None):
                return jsonify({"error": "db_error", "detail": str(r.error)}), 500

        return jsonify({"ok": True, "imported": len(leads),
                        "sample": leads[0] if leads else {}}), 200

    except Exception as e:
        current_app.logger.error(traceback.format_exc())
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/leads/<list_name>', methods=['GET'])
def api_get_leads_by_list(list_name):
    try:
        leads = supabase.table("leads").select("*").eq("list_name", list_name).execute()
        return jsonify({"ok": True, "leads": leads.data}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/lead-campaign-accounts', methods=['GET'])
def api_get_lead_campaign_accounts():
    try:
        accounts = supabase.table("lead_campaign_accounts").select("*").execute()
        return jsonify({"ok": True, "accounts": accounts.data}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/responded-leads', methods=['GET'])
def api_get_responded_leads():
    try:
        leads = supabase.table("responded_leads") \
            .select("*").order("responded_at", desc=True).execute()
        return jsonify({"ok": True, "responded_leads": leads.data}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ── Click tracking ────────────────────────────────────────────────────────────
@app.route('/track/<lead_id>/<campaign_id>')
def track_click(lead_id, campaign_id):
    try:
        url = request.args.get('url')
        if not url:
            return "URL parameter missing", 400

        original_url   = urllib.parse.unquote(url)
        email_queue_id = request.args.get('eqid')

        try:   lid = int(lead_id)
        except: lid = None
        try:   cid = int(campaign_id)
        except: cid = None

        supabase.table("link_clicks").insert({
            "lead_id": lid, "campaign_id": cid,
            "url": original_url, "email_queue_id": email_queue_id,
        }).execute()

        demo_url     = "https://replyzeai.com/goods/templates/demooff"
        redirect_url = f"{demo_url}?lead_id={lead_id}&campaign_id={campaign_id}"
        if email_queue_id:
            redirect_url += f"&eqid={email_queue_id}"
        return redirect(redirect_url)

    except Exception as e:
        print(f"Track error: {e}")
        return "Error tracking click", 500


@app.route('/api/campaigns/<int:campaign_id>/clicks')
def api_get_campaign_clicks(campaign_id):
    try:
        clicks = supabase.table("link_clicks") \
            .select("*, leads(email, name)") \
            .eq("campaign_id", campaign_id) \
            .order("clicked_at", desc=True).execute()
        return jsonify({"ok": True, "clicks": clicks.data}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/leads/<int:lead_id>/clicks')
def api_get_lead_clicks(lead_id):
    try:
        clicks = supabase.table("link_clicks") \
            .select("*, campaigns(name)") \
            .eq("lead_id", lead_id) \
            .order("clicked_at", desc=True).execute()
        return jsonify({"ok": True, "clicks": clicks.data}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/track', methods=['GET'])
def api_track_click():
    try:
        lead_id = request.args.get('lead_id')
        cid     = request.args.get('campaign_id')
        url     = request.args.get('url')
        eqid    = request.args.get('eqid')
        if not all([lead_id, cid, url]):
            return "Missing parameters", 400
        supabase.table("link_clicks").insert({
            "lead_id": lead_id, "campaign_id": cid,
            "url": url, "email_queue_id": eqid,
        }).execute()
        return redirect(url)
    except Exception as e:
        print(f"Track error: {e}")
        return "Error tracking click", 500


# ── Lead details ──────────────────────────────────────────────────────────────
@app.route('/api/leads/<int:lead_id>', methods=['GET'])
def api_get_lead(lead_id):
    try:
        lead = supabase.table("leads").select("*").eq("id", lead_id).single().execute()
        return jsonify({"ok": True, "lead": lead.data}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/leads/<int:lead_id>/ai-usage', methods=['GET'])
def api_get_lead_ai_usage(lead_id):
    try:
        lead = supabase.table("leads").select("email").eq("id", lead_id).single().execute()
        if not lead.data:
            return jsonify({"ok": True, "ai_usage": None}), 200
        ai = supabase.table("ai_demo_usage") \
            .select("*").eq("email", lead.data['email']).execute()
        return jsonify({"ok": True, "ai_usage": ai.data[0] if ai.data else None}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ── AI demo ───────────────────────────────────────────────────────────────────
@app.route('/demo')
def demo():
    return render_template('demo.html',
                           supabase_url=os.environ['SUPABASE_URL'],
                           supabase_anon_key=os.environ['SUPABASE_ANON_KEY'])


@app.route('/api/generate-reply-prompt', methods=['OPTIONS', 'POST'])
def generate_reply_prompt():
    if request.method == "OPTIONS":
        resp = jsonify({"status": "ok"})
        resp.headers.add("Access-Control-Allow-Origin", "https://replyzeai.com")
        resp.headers.add("Access-Control-Allow-Headers", "Content-Type")
        return resp

    data   = request.get_json(force=True)
    prompt = data.get("prompt", "").strip()
    if not prompt:
        return jsonify({"error": "Missing prompt"}), 400

    enhanced = f"""
Generate a professional real estate agent reply to the following email, and then generate three follow-up emails.
Format your response exactly as follows:

=== REPLY ===
[Your main reply here]

=== FOLLOW UP 1 ===
[First follow-up email]

=== FOLLOW UP 2 ===
[Second follow-up email]

=== FOLLOW UP 3 ===
[Third follow-up email]

Email to respond to:
{prompt}
"""
    try:
        GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
        if not GROQ_API_KEY:
            return jsonify({"error": "Groq API key not configured"}), 500

        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}",
                     "Content-Type": "application/json"},
            json={
                "model": "llama-3.1-8b-instant",
                "messages": [
                    {"role": "system", "content": "You are a professional real estate agent."},
                    {"role": "user",   "content": enhanced}
                ],
                "temperature": 0.7, "max_tokens": 1024, "top_p": 0.8
            }, timeout=30
        )
        if r.status_code != 200:
            return jsonify({"error": f"Groq error: {r.status_code}"}), 500

        full     = r.json()["choices"][0]["message"]["content"].strip()
        sections = {}
        cur      = None
        for line in full.split('\n'):
            line = line.strip()
            for key, label in [("=== REPLY ===", "reply"),
                                ("=== FOLLOW UP 1 ===", "fu1"),
                                ("=== FOLLOW UP 2 ===", "fu2"),
                                ("=== FOLLOW UP 3 ===", "fu3")]:
                if line == key:
                    cur = label; sections[cur] = []; break
            else:
                if cur and line:
                    sections[cur].append(line)

        resp = jsonify({
            "reply": ' '.join(sections.get('reply', [])).strip(),
            "follow_ups": [f for f in [
                ' '.join(sections.get('fu1', [])).strip(),
                ' '.join(sections.get('fu2', [])).strip(),
                ' '.join(sections.get('fu3', [])).strip(),
            ] if f]
        })
        resp.headers.add("Access-Control-Allow-Origin", "https://replyzeai.com")
        return resp

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/record-ai-usage', methods=['POST'])
def api_record_ai_usage():
    try:
        data    = request.get_json(force=True)
        lead_id = data.get('lead_id')
        if not lead_id:
            return jsonify({"error": "Lead ID is required"}), 400
        try:
            lead_id = int(lead_id)
        except (ValueError, TypeError):
            pass

        lead = supabase.table("leads").select("email").eq("id", lead_id).single().execute()
        if not lead.data:
            return jsonify({"error": "Lead not found"}), 404

        email    = lead.data['email']
        existing = supabase.table("ai_demo_usage").select("*").eq("email", email).execute()

        if existing.data:
            supabase.table("ai_demo_usage").update({
                "usage_count": existing.data[0]['usage_count'] + 1,
                "last_used_at": datetime.now(timezone.utc).isoformat()
            }).eq("email", email).execute()
        else:
            supabase.table("ai_demo_usage").insert({
                "lead_id": lead_id, "email": email, "usage_count": 1,
                "first_used_at": datetime.now(timezone.utc).isoformat(),
                "last_used_at":  datetime.now(timezone.utc).isoformat(),
            }).execute()

        return jsonify({"ok": True}), 200

    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ── GitHub Actions workflow ───────────────────────────────────────────────────
@app.route('/api/trigger-workflow', methods=['POST'])
def api_trigger_workflow():
    try:
        TOKEN = os.environ.get('GITHUB_TOKEN')
        REPO  = os.environ.get('GITHUB_REPO')
        if not TOKEN or not REPO:
            return jsonify({"error": "GitHub credentials not configured"}), 500

        r = requests.post(
            f"https://api.github.com/repos/{REPO}/actions/workflows/process.yml/dispatches",
            headers={"Authorization": f"Bearer {TOKEN}",
                     "Accept": "application/vnd.github.v3+json"},
            json={"ref": "main"}
        )
        return jsonify({"ok": True}) if r.status_code == 204 \
            else jsonify({"error": f"GitHub API error: {r.status_code}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/workflow-runs', methods=['GET'])
def api_get_workflow_runs():
    try:
        TOKEN = os.environ.get('GITHUB_TOKEN')
        REPO  = os.environ.get('GITHUB_REPO')
        if not TOKEN or not REPO:
            return jsonify({"error": "GitHub credentials not configured"}), 500

        r    = requests.get(
            f"https://api.github.com/repos/{REPO}/actions/runs?per_page=10",
            headers={"Authorization": f"Bearer {TOKEN}",
                     "Accept": "application/vnd.github.v3+json"}
        )
        return jsonify({"ok": True, "runs": r.json().get("workflow_runs", [])}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
#  PILOTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/api/pilots', methods=['GET'])
def api_get_pilots():
    try:
        status = request.args.get('status')
        q = supabase.table("pilots").select("*").order("created_at", desc=True)
        if status:
            q = q.eq("status", status)
        pilots = q.execute()
        return jsonify({"ok": True, "pilots": pilots.data}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/pilots/<int:pilot_id>', methods=['GET'])
def api_get_pilot(pilot_id):
    try:
        pilot = supabase.table("pilots").select("*").eq("id", pilot_id).single().execute()
        if not pilot.data:
            return jsonify({"error": "not_found"}), 404
        return jsonify({"ok": True, "pilot": pilot.data}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/pilots/<int:pilot_id>', methods=['PATCH'])
def api_update_pilot(pilot_id):
    try:
        data = request.get_json(force=True)
        allowed = {
            "status", "inbound_count", "qualified_count", "bookings_confirmed",
            "address", "listing_url", "ops_notes"
        }
        update = {k: v for k, v in data.items() if k in allowed}
        if not update:
            return jsonify({"error": "no_valid_fields"}), 400
        update["updated_at"] = datetime.now(timezone.utc).isoformat()
        supabase.table("pilots").update(update).eq("id", pilot_id).execute()

        if "status" in update:
            supabase.table("reply_audit_log").insert({
                "event_type": "PILOT_STATUS_CHANGED",
                "data": {"pilot_id": pilot_id, "new_status": update["status"]},
                "created_at": datetime.now(timezone.utc).isoformat(),
            }).execute()

        return jsonify({"ok": True}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/pilots/stats', methods=['GET'])
def api_pilots_stats():
    try:
        all_pilots = supabase.table("pilots").select("status").execute()
        counts: dict = {}
        for p in all_pilots.data:
            s = p.get("status", "unknown")
            counts[s] = counts.get(s, 0) + 1

        total  = len(all_pilots.data)
        active = counts.get("active", 0) + counts.get("running", 0)

        pr = supabase.table("processed_replies") \
            .select("intent") \
            .neq("intent", "NOT_A_LEAD") \
            .neq("intent", "DO_NOT_CONTACT") \
            .execute()
        intent_counts: dict = {}
        for row in pr.data:
            i = row.get("intent", "UNKNOWN")
            intent_counts[i] = intent_counts.get(i, 0) + 1

        unsub_count = (
            supabase.table("leads").select("id", count="exact")
                .eq("do_not_contact", True).execute().count or 0
        )

        return jsonify({
            "ok": True,
            "stats": {
                "pilots_total":       total,
                "pilots_active":      active,
                "pilots_by_status":   counts,
                "replies_by_intent":  intent_counts,
                "unsubscribes":       unsub_count,
                "replies_total":      len(pr.data),
            }
        }), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
#  OPS TICKETS
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/api/ops-tickets', methods=['GET'])
def api_get_ops_tickets():
    try:
        status = request.args.get('status', 'open')
        tickets = supabase.table("ops_tickets") \
            .select("*") \
            .eq("status", status) \
            .order("created_at", desc=True) \
            .execute()
        return jsonify({"ok": True, "tickets": tickets.data}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/ops-tickets/<int:ticket_id>/resolve', methods=['POST'])
def api_resolve_ticket(ticket_id):
    try:
        data = request.get_json(force=True)
        supabase.table("ops_tickets").update({
            "status":      "resolved",
            "resolved_by": data.get("resolved_by", "admin"),
            "resolved_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", ticket_id).execute()
        notify(
            '✅ Ticket Resolved',
            f'Ticket #{ticket_id} was resolved by {data.get("resolved_by", "admin")}.',
            priority='low', tags='white_check_mark',
        )
        return jsonify({"ok": True}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/ops-tickets/<int:ticket_id>/spam', methods=['POST'])
def api_spam_ticket(ticket_id):
    try:
        supabase.table("ops_tickets").update({"status": "spam"}) \
            .eq("id", ticket_id).execute()
        return jsonify({"ok": True}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
#  AUDIT LOG
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/api/reply-audit', methods=['GET'])
def api_get_reply_audit():
    try:
        limit      = int(request.args.get('limit', 100))
        event_type = request.args.get('event_type')
        q = supabase.table("reply_audit_log").select("*") \
                .order("created_at", desc=True).limit(limit)
        if event_type:
            q = q.eq("event_type", event_type)
        logs = q.execute()
        return jsonify({"ok": True, "logs": logs.data}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
#  PROCESSED REPLIES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/api/processed-replies', methods=['GET'])
def api_get_processed_replies():
    try:
        limit  = int(request.args.get('limit', 50))
        intent = request.args.get('intent')
        q = supabase.table("processed_replies").select("*") \
                .neq("intent", "NOT_A_LEAD") \
                .neq("intent", "DO_NOT_CONTACT") \
                .order("processed_at", desc=True) \
                .limit(limit)
        if intent:
            q = q.eq("intent", intent)
        replies = q.execute()
        return jsonify({"ok": True, "replies": replies.data}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
#  MANUAL OVERRIDE
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/api/manual-reply', methods=['POST'])
def api_manual_reply():
    try:
        data         = request.get_json(force=True)
        to_email     = data.get('to_email', '').strip()
        subject      = data.get('subject', '').strip()
        body         = data.get('body', '').strip()
        pref_account = data.get('gmail_account', '').strip()

        if not to_email or not body:
            return jsonify({"error": "to_email and body required"}), 400

        if pref_account:
            acct_r = supabase.table("gmail_accounts").select("*") \
                         .eq("email", pref_account).single().execute()
            account = acct_r.data
        else:
            accts = supabase.table("gmail_accounts") \
                        .select("*").eq("gmail_connected", True).execute()
            account = accts.data[0] if accts.data else None

        if not account:
            return jsonify({"error": "no_gmail_account_available"}), 400

        token_resp = requests.post(GOOGLE_TOKEN_URL, data={
            "client_id":     GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "refresh_token": aesgcm_decrypt(account["encrypted_refresh_token"]),
            "grant_type":    "refresh_token",
        }, timeout=15)

        if token_resp.status_code != 200:
            return jsonify({"error": "token_refresh_failed"}), 400

        access_token = token_resp.json().get("access_token")

        from email.mime.text import MIMEText as _MIME
        msg            = _MIME(body.replace('\n', '<br>'), "html", "utf-8")
        msg["To"]      = to_email
        msg["From"]    = f"{account['display_name']} <{account['email']}>"
        msg["Subject"] = subject

        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8").rstrip("=")
        send_resp = requests.post(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            headers={"Authorization": f"Bearer {access_token}",
                     "Content-Type": "application/json"},
            json={"raw": raw},
            timeout=30,
        )

        if send_resp.status_code in (200, 201):
            supabase.table("reply_audit_log").insert({
                "event_type": "MANUAL_REPLY_SENT",
                "data": {"to": to_email, "subject": subject, "account": account['email']},
                "created_at": datetime.now(timezone.utc).isoformat(),
            }).execute()
            notify(
                '📤 Manual Reply Sent',
                f'To: {to_email}\nSubject: {subject or "(no subject)"}\nFrom: {account["email"]}',
                priority='low', tags='outbox_tray',
            )
            return jsonify({"ok": True}), 200

        return jsonify({"error": "send_failed", "detail": send_resp.text}), 400

    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
#  NOTIFICATION TEST ENDPOINTS  (called from the Notifications tab in admin)
# ═══════════════════════════════════════════════════════════════════════════════

import time as _time

_TEST_EVENTS = {
    'pilot_created':     ('🏠 Pilot Created',         'john.smith@kw.com sent a listing URL → 123 Maple St Denver CO 80203\nSubject: Re: Your listing',         'high',    'house,rotating_light'),
    'yes_no_url':        ('📋 Agent Interested',       'sarah.jones@realty.com is interested but hasn\'t shared a URL yet.\nSubject: Re: Free pilot offer',        'high',    'memo,rotating_light'),
    'forwarded_lead':    ('📨 Forwarded Lead',         'mike.broker@compass.com forwarded a buyer lead.\nSubject: Fwd: Interested in your listing',                'high',    'inbox_tray,rotating_light'),
    'negative':          ('⚠️ Negative Objection',    'angry.agent@gmail.com\n"Stop emailing me, my listing is already under contract and your info is wrong!"',  'high',    'warning'),
    'auto_reply_failed': ('❌ Auto-Reply Failed',      'Could not send auto-reply to broken@domain.com\nIntent: YES_NO_URL\nAccount: outreach@replyzeai.com',      'high',    'x,warning'),
    'asks_price':        ('💰 Pricing Question',       'curious.agent@kw.com asked about pricing.\nSubject: How much does this cost?',                             'default', 'moneybag'),
    'asks_details':      ('❓ Details Question',       'tech.savvy@compass.com asked how the system works.\nSubject: How does the setup work?',                    'default', 'question'),
    'unsubscribe':       ('🚫 Unsubscribe',            'opt.out@gmail.com opted out and was marked do-not-contact.',                                               'low',     'no_entry'),
    'run_complete':      ('📬 Reply Run Complete',     '5 message(s) processed across 2 account(s).',                                                              'low',     'email'),
    'campaign_queued':   ('📣 Campaign Queued',        '"Spring Outreach 2026" → 342 emails queued immediately.',                                                  'default', 'loudspeaker'),
    'manual_reply_sent': ('📤 Manual Reply Sent',      'To: vip.lead@gmail.com\nSubject: Following up on your question\nFrom: outreach@replyzeai.com',             'low',     'outbox_tray'),
    'ticket_resolved':   ('✅ Ticket Resolved',        'Ticket #42 was resolved by admin.',                                                                        'low',     'white_check_mark'),
    'batch_done':        ('📧 15 Emails Sent',         'Batch complete — 15 email(s) delivered successfully.',                                                     'low',     'email'),
    'send_limit':        ('⚠️ Daily Limit Reached',   'All SMTP accounts have hit their 50-email daily limit. No emails sent until tomorrow.',                    'high',    'warning'),
}
_HIGH_PRIORITY_EVENTS = {k for k, v in _TEST_EVENTS.items() if v[2] == 'high'}


@app.route('/api/notify/test', methods=['POST'])
def api_notify_test():
    """Send a custom one-off push notification from the admin panel."""
    try:
        data     = request.get_json(force=True)
        title    = data.get('title', 'Test').strip()[:100]
        message  = data.get('message', 'Hello').strip()[:500]
        priority = data.get('priority', 'default')
        tags     = data.get('tags', '')
        if priority not in ('urgent', 'high', 'default', 'low', 'min'):
            priority = 'default'
        notify(title, message, priority=priority, tags=tags)
        return jsonify({'ok': True}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/notify/test-event', methods=['POST'])
def api_notify_test_event():
    """Fire a single named test notification."""
    try:
        data  = request.get_json(force=True)
        key   = data.get('event', '').strip()
        if key not in _TEST_EVENTS:
            return jsonify({'error': f'Unknown event key: {key!r}'}), 400
        title, message, priority, tags = _TEST_EVENTS[key]
        notify(title, message, priority=priority, tags=tags)
        return jsonify({'ok': True, 'fired': key}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/notify/test-all', methods=['POST'])
def api_notify_test_all():
    """Fire all test notifications (or only high-priority ones) — no sleep, pacing done in JS."""
    try:
        data       = request.get_json(force=True)
        filt       = data.get('filter', 'all')  # 'all' | 'high'
        keys       = list(_TEST_EVENTS.keys())
        if filt == 'high':
            keys = [k for k in keys if k in _HIGH_PRIORITY_EVENTS]
        for k in keys:
            title, message, priority, tags = _TEST_EVENTS[k]
            notify(title, message, priority=priority, tags=tags)
        return jsonify({"ok": True, "fired": len(keys), "events": keys}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
