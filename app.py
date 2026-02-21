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
import requests
import urllib.parse
from datetime import datetime, timedelta, timezone, date
from flask import (Flask, request, redirect, render_template,
                   jsonify, current_app, url_for)
from flask_cors import CORS
from dotenv import load_dotenv
from supabase import create_client
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from email_validator import validate_email, EmailNotValidError

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


# ─────────────────────────────────────────────────────────────────────────────
#  GMAIL OAUTH FLOW
#
#  Step 1 – /auth/gmail
#    Admin clicks "Connect Gmail Account" → browser redirects to Google's
#    consent screen requesting gmail.send + userinfo scopes.
#
#  Step 2 – Google redirects to /auth/gmail/callback
#    We exchange the auth code for access_token + refresh_token, then call
#    the userinfo endpoint to learn which Gmail address just connected.
#    The refresh_token is AES-GCM encrypted and stored in gmail_accounts.
#
#  Step 3 – Done. Admin dashboard shows the account as connected.
# ─────────────────────────────────────────────────────────────────────────────

# ── Stateless OAuth state helpers ────────────────────────────────────────────
# We sign the state token with HMAC-SHA256 using ENCRYPTION_KEY so we never
# need Flask sessions.  This works across restarts, multiple workers, and any
# reverse-proxy setup that might strip session cookies.
import hmac
import hashlib
import time

def _make_oauth_state() -> str:
    """
    Create a signed state token:  {nonce}.{timestamp}.{hmac}
    Valid for 10 minutes.
    """
    nonce     = secrets.token_urlsafe(24)
    ts        = str(int(time.time()))
    payload   = f"{nonce}.{ts}"
    sig       = hmac.new(ENCRYPTION_KEY[:32], payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"

def _verify_oauth_state(state: str, max_age: int = 600) -> bool:
    """
    Verify the HMAC signature and that the token is < max_age seconds old.
    Returns True only if both checks pass.
    """
    try:
        parts = state.rsplit('.', 1)          # split off the hex sig at the end
        if len(parts) != 2:
            return False
        payload, sig = parts
        expected = hmac.new(ENCRYPTION_KEY[:32], payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False
        # Extract timestamp (second segment of payload)
        _, ts = payload.split('.', 1)
        if int(time.time()) - int(ts) > max_age:
            return False
        return True
    except Exception:
        return False


@app.route('/auth/gmail')
def auth_gmail():
    """Kick off OAuth – redirect user to Google's consent screen."""
    if not GOOGLE_CLIENT_ID:
        return "GOOGLE_CLIENT_ID not configured", 500

    # CSRF protection: HMAC-signed stateless token (no Flask session needed)
    state = _make_oauth_state()

    params = {
        "client_id":     GOOGLE_CLIENT_ID,
        "redirect_uri":  GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope":         " ".join(GMAIL_SCOPES),
        "access_type":   "offline",   # REQUIRED to get refresh_token
        "prompt":        "consent",   # REQUIRED – forces refresh_token even if
                                      # user already authorised this app before
        "state":         state,
    }
    auth_url = GOOGLE_AUTH_URL + "?" + urllib.parse.urlencode(params)
    return redirect(auth_url)


@app.route('/auth/gmail/callback')
def auth_gmail_callback():
    """Google redirects here after user consents."""
    # ── CSRF check (stateless HMAC verify – no session required) ────────────
    returned_state = request.args.get('state', '')
    if not returned_state or not _verify_oauth_state(returned_state):
        return "OAuth state invalid or expired. Please try connecting again.", 400

    error = request.args.get('error')
    if error:
        return redirect(f"/admin?oauth_error={urllib.parse.quote(error)}")

    code = request.args.get('code')
    if not code:
        return "Missing auth code from Google.", 400

    # ── Exchange code for tokens ─────────────────────────────────────────────
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
        # This happens if the user already authorised the app without
        # prompt=consent. The /auth/gmail route sets prompt=consent so this
        # should never happen, but guard anyway.
        return ("No refresh_token returned. "
                "Please revoke app access in your Google account and try again."), 400

    # ── Get the user's email address from Google ─────────────────────────────
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

    # ── Encrypt & store in Supabase ──────────────────────────────────────────
    encrypted_rt = aesgcm_encrypt(refresh_token)

    supabase.table("gmail_accounts").upsert({
        "email":                   email,
        "display_name":            display_name,
        "encrypted_refresh_token": encrypted_rt,
        "gmail_connected":         True,
    }, on_conflict="email").execute()

    return redirect("/admin?oauth_success=1")


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
    """
    Disconnect & remove a Gmail account.
    Also attempts to revoke the token from Google's side.
    """
    try:
        acct = supabase.table("gmail_accounts") \
            .select("encrypted_refresh_token, email") \
            .eq("id", account_id) \
            .single() \
            .execute()

        if not acct.data:
            return jsonify({"error": "Account not found"}), 404

        # Try to revoke token at Google (best-effort)
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
    """Send a test email to the account itself to verify the token works."""
    try:
        acct = supabase.table("gmail_accounts") \
            .select("*").eq("id", account_id).single().execute()

        if not acct.data:
            return jsonify({"error": "Account not found"}), 404

        account = acct.data

        # Get fresh access token
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

        # Build a minimal test message
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


# ── Campaigns ─────────────────────────────────────────────────────────────────
@app.route('/api/campaigns', methods=['GET'])
def api_get_campaigns():
    try:
        campaigns = supabase.table("campaigns") \
            .select("*").order("created_at", desc=True).execute()
        return jsonify({"ok": True, "campaigns": campaigns.data}), 200
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
        for enc in ('utf-8', 'latin-1', 'windows-1252', 'iso-8859-1'):
            try:
                decoded = raw.decode(enc); break
            except UnicodeDecodeError:
                continue
        if decoded is None:
            decoded = raw.decode('latin-1')

        reader = csv.DictReader(io.StringIO(decoded))

        if not reader.fieldnames:
            return jsonify({"error": "CSV has no headers"}), 400
        if 'email' not in [h.lower() for h in reader.fieldnames]:
            return jsonify({"error": "CSV must contain an email column"}), 400

        HEADER_ALIASES = {
            "ai hook": "ai hooks", "ai hooks": "ai hooks", "ai_hook": "ai hooks",
            "lastsale": "last sale", "last sale": "last sale", "last_sale": "last sale",
            "openhouse": "open house", "open house": "open house", "open_house": "open house",
            "lastname": "last name", "last_name": "last name",
        }
        STANDARD_FIELDS = {
            "email", "name", "last name", "city", "brokerage",
            "service", "street", "ai hooks", "open house", "last sale",
        }

        leads_by_email = {}
        for row in reader:
            if not row:
                continue
            cleaned = {}
            for k, v in row.items():
                if not k:
                    continue
                key = HEADER_ALIASES.get(k.strip().lower(), k.strip().lower())
                cleaned[key] = v.strip() if v else ""

            email = cleaned.get("email", "").lower()
            if not email:
                continue
            try:
                validate_email(email)
            except EmailNotValidError:
                continue

            leads_by_email[email] = {
                "email":         email,
                "name":          cleaned.get("name", ""),
                "last_name":     cleaned.get("last name", ""),
                "city":          cleaned.get("city", ""),
                "brokerage":     cleaned.get("brokerage", ""),
                "service":       cleaned.get("service", ""),
                "street":        cleaned.get("street", ""),
                "ai_hooks":      cleaned.get("ai hooks", ""),
                "open_house":    cleaned.get("open house", ""),
                "last_sale":     cleaned.get("last sale", ""),
                "list_name":     list_name,
                "custom_fields": {k: v for k, v in cleaned.items()
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
