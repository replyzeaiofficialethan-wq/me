# app.py
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
import smtplib
import imaplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone, date
from flask import Flask, request, redirect, render_template, jsonify, current_app
from flask_cors import CORS
from dotenv import load_dotenv
from supabase import create_client
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from email_validator import validate_email, EmailNotValidError
from urllib.parse import urlencode
import urllib.parse

load_dotenv()

# ---------- Supabase ----------
SUPABASE_URL = os.environ['SUPABASE_URL']
SUPABASE_KEY = os.environ['SUPABASE_SERVICE_ROLE_KEY']
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# ---------- Encryption ----------
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
    aesgcm = AESGCM(ENCRYPTION_KEY)
    pt     = aesgcm.decrypt(nonce, ct, None)
    return pt.decode('utf-8')


# ---------------------------------------------------------------------------
# Spintax engine  –  syntax: {{option A|option B|option C}}
# ---------------------------------------------------------------------------
def process_spintax(text: str) -> str:
    """
    Resolve all {{opt1|opt2|...}} groups in *text* by randomly picking
    one option per group.  Nested groups are supported (inside-out resolution).

    Example:
        "{{Hi|Hello}} {name}, {{great to meet you|nice connecting}}!"
        → "Hello John, great to meet you!"   (one possible permutation)
    """
    pattern = re.compile(r'\{\{([^{}]+?)\}\}')
    while True:
        match = pattern.search(text)
        if not match:
            break
        options = match.group(1).split('|')
        chosen  = random.choice(options)
        text    = text[:match.start()] + chosen + text[match.end():]
    return text


# ---------------------------------------------------------------------------
# Template rendering  (spintax FIRST → variable substitution → HTML escaping)
# ---------------------------------------------------------------------------
def render_email_template(template: str, lead_data: dict) -> str:
    """
    1. Resolve {{spintax}} groups  → unique random permutation per call.
    2. Replace {variable} tokens   → lead data.
    3. Convert newlines to <br>    → HTML email safe.

    Because process_spintax() is called per-lead, every recipient receives
    a statistically unique version of the message even when sharing the same
    campaign template.
    """
    # Step 1 – spintax
    rendered = process_spintax(template)

    # Step 2 – lead variable substitution
    for key, value in lead_data.items():
        if value is None:
            value = ""
        rendered = rendered.replace("{" + str(key) + "}", str(value))
        rendered = rendered.replace("{" + str(key).replace('_', ' ') + "}", str(value))

    # Step 3 – HTML whitespace
    rendered = rendered.replace('\n', '<br>')
    rendered = rendered.replace('  ', '&nbsp;&nbsp;')

    return rendered


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__, template_folder="templates")

CORS(app, resources={
    r"/api/*": {
        "origins": [
            "replyzeai.com",
            "replyzeai.com/demooff",
        ],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "Origin"]
    }
})


# ---------- Routes ----------
@app.route('/')
def index():
    return render_template('admin.html')

@app.route('/admin')
def admin():
    return render_template('admin.html')


# ---------- SMTP Accounts ----------
@app.route('/api/smtp-accounts', methods=['GET'])
def api_get_smtp_accounts():
    try:
        accounts = supabase.table("smtp_accounts").select("*").execute()
        return jsonify({"ok": True, "accounts": accounts.data}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/smtp-accounts', methods=['POST'])
def api_add_smtp_account():
    try:
        data = request.get_json(force=True)

        # Test connection before storing
        try:
            smtp = smtplib.SMTP(data['smtp_host'], data['smtp_port'])
            smtp.starttls()
            smtp.login(data['smtp_username'], data['smtp_password'])
            smtp.quit()
        except Exception as e:
            return jsonify({"error": "smtp_connection_failed", "detail": str(e)}), 400

        encrypted_password = aesgcm_encrypt(data['smtp_password'])

        account_data = {
            "email":                    data['email'],
            "display_name":             data.get('display_name', data['email']),
            "smtp_host":                data['smtp_host'],
            "smtp_port":                data['smtp_port'],
            "smtp_username":            data['smtp_username'],
            "encrypted_smtp_password":  encrypted_password,
            "imap_host":                data.get('imap_host'),
            "imap_port":                data.get('imap_port')
        }

        result = supabase.table("smtp_accounts").insert(account_data).execute()
        if getattr(result, "error", None):
            return jsonify({"error": "db_error", "detail": str(result.error)}), 500

        return jsonify({"ok": True, "account": result.data[0]}), 200

    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ---------- Account Status ----------
@app.route('/api/account-status', methods=['GET'])
def api_get_account_status():
    try:
        today    = date.today().isoformat()
        accounts = supabase.table("smtp_accounts").select("*").execute()

        statuses = []
        for account in accounts.data:
            count_data = supabase.table("daily_email_counts") \
                .select("count") \
                .eq("email_account", account["email"]) \
                .eq("date", today) \
                .execute()

            count = count_data.data[0]["count"] if count_data.data else 0
            statuses.append({
                "email":          account["email"],
                "display_name":   account["display_name"],
                "sent_today":     count,
                "remaining_today": 100 - count
            })

        return jsonify({"ok": True, "accounts": statuses}), 200

    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ---------- Campaigns ----------
@app.route('/api/campaigns', methods=['GET'])
def api_get_campaigns():
    try:
        campaigns = supabase.table("campaigns").select("*").order("created_at", desc=True).execute()
        return jsonify({"ok": True, "campaigns": campaigns.data}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/campaigns', methods=['POST'])
def api_create_campaign():
    try:
        data = request.get_json(force=True)

        campaign_data = {
            "name":             data.get('name'),
            "subject":          data.get('subject'),
            "body":             data.get('body'),
            "list_name":        data.get('list_name'),
            "send_immediately": data.get('send_immediately', False)
        }

        result = supabase.table("campaigns").insert(campaign_data).execute()
        if getattr(result, "error", None):
            return jsonify({"error": "db_error", "detail": str(result.error)}), 500

        campaign    = result.data[0]
        campaign_id = campaign['id']

        # Insert follow-ups
        follow_ups = data.get('follow_ups', [])
        for i, follow_up in enumerate(follow_ups):
            supabase.table("campaign_followups").insert({
                "campaign_id":        campaign_id,
                "subject":            follow_up.get('subject'),
                "body":               follow_up.get('body'),
                "days_after_previous": follow_up.get('days_after', 1),
                "sequence":           i + 1
            }).execute()

        # Queue initial emails if send_immediately
        if data.get('send_immediately'):
            leads = supabase.table("leads") \
                .select("*") \
                .eq("list_name", data.get('list_name')) \
                .execute()

            if leads.data:
                email_queue = []
                for lead in leads.data:
                    # Each lead gets its own spintax resolution → unique permutation
                    rendered_subject = render_email_template(data.get('subject', ''), lead)
                    rendered_body    = render_email_template(data.get('body', ''),    lead)

                    email_queue.append({
                        "campaign_id":   campaign_id,
                        "lead_id":       lead['id'],
                        "lead_email":    lead['email'],
                        "subject":       rendered_subject,
                        "body":          rendered_body,
                        "sequence":      0,
                        "scheduled_for": datetime.now(timezone.utc).isoformat()
                    })

                CHUNK_SIZE = 100
                for i in range(0, len(email_queue), CHUNK_SIZE):
                    supabase.table("email_queue").insert(email_queue[i:i+CHUNK_SIZE]).execute()

                print(f"Queued {len(email_queue)} emails (spintax resolved per-lead)")

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
            return jsonify({"error": "campaign_id and sequence are required"}), 400

        campaign  = supabase.table("campaigns").select("*").eq("id", campaign_id).single().execute()
        follow_up = supabase.table("campaign_followups") \
            .select("*") \
            .eq("campaign_id", campaign_id) \
            .eq("sequence", sequence) \
            .single() \
            .execute()

        if not campaign.data or not follow_up.data:
            return jsonify({"error": "Campaign or follow-up not found"}), 404

        leads = supabase.table("leads") \
            .select("*") \
            .eq("list_name", campaign.data['list_name']) \
            .execute()

        if not leads.data:
            return jsonify({"ok": True, "queued": 0}), 200

        days_delay  = follow_up.data['days_after_previous']
        send_date   = datetime.now(timezone.utc) + timedelta(days=days_delay)
        email_queue = []

        for lead in leads.data:
            # Fresh spintax resolution per lead
            rendered_subject = render_email_template(follow_up.data['subject'], lead)
            rendered_body    = render_email_template(follow_up.data['body'],    lead)

            email_queue.append({
                "campaign_id":   campaign_id,
                "lead_id":       lead['id'],
                "lead_email":    lead['email'],
                "subject":       rendered_subject,
                "body":          rendered_body,
                "sequence":      sequence,
                "scheduled_for": send_date.isoformat()
            })

        CHUNK_SIZE   = 100
        total_queued = 0
        for i in range(0, len(email_queue), CHUNK_SIZE):
            chunk = email_queue[i:i+CHUNK_SIZE]
            supabase.table("email_queue").insert(chunk).execute()
            total_queued += len(chunk)

        return jsonify({"ok": True, "queued": total_queued}), 200

    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ---------- Leads ----------
@app.route('/api/leads/lists', methods=['GET'])
def api_get_lead_lists():
    try:
        query = supabase.table("leads").select("list_name").execute()
        list_counts = {}
        for lead in query.data:
            name = lead.get('list_name', 'Unknown')
            if name:
                list_counts[name] = list_counts.get(name, 0) + 1
        lists = [{"list_name": n, "lead_count": c} for n, c in list_counts.items()]
        return jsonify({"ok": True, "lists": lists}), 200
    except Exception as e:
        current_app.logger.error("Error in api_get_lead_lists: %s", traceback.format_exc())
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
                decoded = raw.decode(enc)
                break
            except UnicodeDecodeError:
                continue
        if decoded is None:
            decoded = raw.decode('latin-1')

        stream = io.StringIO(decoded)
        reader = csv.DictReader(stream)

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
                key = k.strip().lower()
                key = HEADER_ALIASES.get(key, key)
                cleaned[key] = v.strip() if v else ""

            email = cleaned.get("email", "").lower()
            if not email:
                continue
            try:
                validate_email(email)
            except EmailNotValidError:
                continue

            custom_fields = {k: v for k, v in cleaned.items() if k not in STANDARD_FIELDS}
            leads_by_email[email] = {
                "email":       email,
                "name":        cleaned.get("name", ""),
                "last_name":   cleaned.get("last name", ""),
                "city":        cleaned.get("city", ""),
                "brokerage":   cleaned.get("brokerage", ""),
                "service":     cleaned.get("service", ""),
                "street":      cleaned.get("street", ""),
                "ai_hooks":    cleaned.get("ai hooks", ""),
                "open_house":  cleaned.get("open house", ""),
                "last_sale":   cleaned.get("last sale", ""),
                "list_name":   list_name,
                "custom_fields": custom_fields
            }

        leads = list(leads_by_email.values())
        if leads:
            CHUNK_SIZE = 100
            for i in range(0, len(leads), CHUNK_SIZE):
                result = supabase.table("leads") \
                    .upsert(leads[i:i+CHUNK_SIZE], on_conflict="email") \
                    .execute()
                if getattr(result, "error", None):
                    return jsonify({"error": "db_error", "detail": str(result.error)}), 500

        return jsonify({"ok": True, "imported": len(leads), "sample": leads[0] if leads else {}}), 200

    except Exception as e:
        current_app.logger.error("Lead import failed:\n%s", traceback.format_exc())
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
        leads = supabase.table("responded_leads").select("*").order("responded_at", desc=True).execute()
        return jsonify({"ok": True, "responded_leads": leads.data}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ---------- Click Tracking ----------
@app.route('/track/<lead_id>/<campaign_id>')
def track_click(lead_id, campaign_id):
    try:
        url = request.args.get('url')
        if not url:
            return "URL parameter missing", 400
        original_url    = urllib.parse.unquote(url)
        email_queue_id  = request.args.get('eqid', None)

        try:
            lead_id_int     = int(lead_id)
        except (ValueError, TypeError):
            lead_id_int     = None
        try:
            campaign_id_int = int(campaign_id)
        except (ValueError, TypeError):
            campaign_id_int = None

        supabase.table("link_clicks").insert({
            "lead_id":        lead_id_int,
            "campaign_id":    campaign_id_int,
            "url":            original_url,
            "email_queue_id": email_queue_id
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
            .order("clicked_at", desc=True) \
            .execute()
        return jsonify({"ok": True, "clicks": clicks.data}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/leads/<int:lead_id>/clicks')
def api_get_lead_clicks(lead_id):
    try:
        clicks = supabase.table("link_clicks") \
            .select("*, campaigns(name)") \
            .eq("lead_id", lead_id) \
            .order("clicked_at", desc=True) \
            .execute()
        return jsonify({"ok": True, "clicks": clicks.data}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


@app.route('/api/track', methods=['GET'])
def api_track_click():
    try:
        lead_id        = request.args.get('lead_id')
        campaign_id    = request.args.get('campaign_id')
        url            = request.args.get('url')
        email_queue_id = request.args.get('eqid', None)

        if not all([lead_id, campaign_id, url]):
            return "Missing parameters", 400

        supabase.table("link_clicks").insert({
            "lead_id":        lead_id,
            "campaign_id":    campaign_id,
            "url":            url,
            "email_queue_id": email_queue_id
        }).execute()
        return redirect(url)
    except Exception as e:
        print(f"Track error: {e}")
        return "Error tracking click", 500


# ---------- Lead details ----------
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
        ai_usage = supabase.table("ai_demo_usage") \
            .select("*") \
            .eq("email", lead.data['email']) \
            .execute()
        return jsonify({"ok": True, "ai_usage": ai_usage.data[0] if ai_usage.data else None}), 200
    except Exception as e:
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ---------- AI demo ----------
@app.route('/demo')
def demo():
    return render_template('demo.html',
                           supabase_url=os.environ['SUPABASE_URL'],
                           supabase_anon_key=os.environ['SUPABASE_ANON_KEY'])


@app.route('/api/generate-reply-prompt', methods=['OPTIONS', 'POST'])
def generate_reply_prompt():
    if request.method == "OPTIONS":
        response = jsonify({"status": "ok"})
        response.headers.add("Access-Control-Allow-Origin", "https://replyzeai.com")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        return response

    data   = request.get_json(force=True)
    prompt = data.get("prompt", "").strip()
    if not prompt:
        return jsonify({"error": "Missing prompt"}), 400

    enhanced_prompt = f"""
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

        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model":       "llama-3.1-8b-instant",
                "messages": [
                    {"role": "system", "content": "You are a professional real estate agent. Generate concise, professional responses that help convert leads into appointments."},
                    {"role": "user",   "content": enhanced_prompt}
                ],
                "temperature": 0.7,
                "max_tokens":  1024,
                "top_p":       0.8
            },
            timeout=30
        )

        if response.status_code != 200:
            return jsonify({"error": f"Groq API error: {response.status_code}"}), 500

        result        = response.json()
        full_response = result["choices"][0]["message"]["content"].strip()
        sections      = {}
        current_section = None
        for line in full_response.split('\n'):
            line = line.strip()
            for key, label in [("=== REPLY ===", "reply"),
                                ("=== FOLLOW UP 1 ===", "follow_up_1"),
                                ("=== FOLLOW UP 2 ===", "follow_up_2"),
                                ("=== FOLLOW UP 3 ===", "follow_up_3")]:
                if line == key:
                    current_section = label
                    sections[current_section] = []
                    break
            else:
                if current_section and line:
                    sections[current_section].append(line)

        reply     = ' '.join(sections.get('reply', [])).strip()
        follow_ups = [
            ' '.join(sections.get('follow_up_1', [])).strip(),
            ' '.join(sections.get('follow_up_2', [])).strip(),
            ' '.join(sections.get('follow_up_3', [])).strip()
        ]
        follow_ups = [fu for fu in follow_ups if fu]

        resp = jsonify({"reply": reply, "follow_ups": follow_ups})
        resp.headers.add("Access-Control-Allow-Origin", "https://replyzeai.com")
        return resp

    except Exception as e:
        print(f"Groq error: {e}")
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
                "lead_id":      lead_id,
                "email":        email,
                "usage_count":  1,
                "first_used_at": datetime.now(timezone.utc).isoformat(),
                "last_used_at":  datetime.now(timezone.utc).isoformat()
            }).execute()

        return jsonify({"ok": True}), 200

    except Exception as e:
        print(f"AI usage record error: {e}")
        return jsonify({"error": "internal_server_error", "detail": str(e)}), 500


# ---------- Workflow ----------
@app.route('/api/trigger-workflow', methods=['POST'])
def api_trigger_workflow():
    try:
        GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')
        GITHUB_REPO  = os.environ.get('GITHUB_REPO')  # "owner/repo"
        if not GITHUB_TOKEN or not GITHUB_REPO:
            return jsonify({"error": "GitHub credentials not configured"}), 500

        response = requests.post(
            f"https://api.github.com/repos/{GITHUB_REPO}/actions/workflows/process.yml/dispatches",
            headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Accept":        "application/vnd.github.v3+json"
            },
            json={"ref": "main"}
        )
        if response.status_code == 204:
            return jsonify({"ok": True}), 200
        return jsonify({"error": f"GitHub API error: {response.status_code}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/workflow-runs', methods=['GET'])
def api_get_workflow_runs():
    try:
        GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')
        GITHUB_REPO  = os.environ.get('GITHUB_REPO')
        if not GITHUB_TOKEN or not GITHUB_REPO:
            return jsonify({"error": "GitHub credentials not configured"}), 500

        response = requests.get(
            f"https://api.github.com/repos/{GITHUB_REPO}/actions/runs?per_page=10",
            headers={
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Accept":        "application/vnd.github.v3+json"
            }
        )
        data = response.json()
        runs = data.get("workflow_runs", [])
        return jsonify({"ok": True, "runs": runs}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
