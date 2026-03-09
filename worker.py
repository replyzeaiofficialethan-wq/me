# worker.py
import os
import smtplib
import base64
from email.mime.text import MIMEText
from datetime import datetime, timedelta, date, timezone
from supabase import create_client
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import urllib.parse
import re
from notify import notify  # ← ntfy.sh push notifications

# Initialize Supabase
SUPABASE_URL = os.environ['SUPABASE_URL']
SUPABASE_KEY = os.environ['SUPABASE_SERVICE_ROLE_KEY']
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Encryption functions
ENCRYPTION_KEY = bytes.fromhex(os.environ['ENCRYPTION_KEY'])




print(f"DEBUG: Environment check")
print(f"DEBUG: Checking for BASE_URL env var: {os.environ.get('BASE_URL', 'NOT SET')}")
print(f"DEBUG: Checking for TRACKING_DOMAIN env var: {os.environ.get('TRACKING_DOMAIN', 'NOT SET')}")
print(f"DEBUG: Checking for APP_URL env var: {os.environ.get('APP_URL', 'NOT SET')}")

def aesgcm_decrypt(b64text: str) -> str:
    data = base64.b64decode(b64text)
    nonce = data[:12]
    ct = data[12:]
    aesgcm = AESGCM(ENCRYPTION_KEY)
    pt = aesgcm.decrypt(nonce, ct, None)
    return pt.decode('utf-8')

def send_email_via_smtp(account, to_email, subject, html_body):
    """Send email using SMTP"""
    try:
        # Decrypt SMTP password
        smtp_password = aesgcm_decrypt(account["encrypted_smtp_password"])
        
        # Create message
        msg = MIMEText(html_body, "html")
        msg["Subject"] = subject
        msg["From"] = f"{account['display_name']} <{account['email']}>"
        msg["To"] = to_email
        
        # Send email
        smtp = smtplib.SMTP(account["smtp_host"], account["smtp_port"])
        smtp.starttls()  # Use TLS
        smtp.login(account["smtp_username"], smtp_password)
        smtp.send_message(msg)
        smtp.quit()
        return True
    except Exception as e:
        print(f"Error sending email via SMTP: {str(e)}")
        return False

def get_account_for_lead_campaign(lead_id, campaign_id):
    """Get the assigned SMTP account for a lead/campaign combination"""
    try:
        # Check if we already have an account assigned for this lead/campaign
        assignment = supabase.table("lead_campaign_accounts") \
            .select("smtp_account") \
            .eq("lead_id", lead_id) \
            .eq("campaign_id", campaign_id) \
            .execute()
        
        if assignment.data:
            # Get the account details
            account = supabase.table("smtp_accounts") \
                .select("*") \
                .eq("email", assignment.data[0]["smtp_account"]) \
                .single() \
                .execute()
            return account.data
        return None
    except:
        return None

def assign_account_to_lead_campaign(lead_id, campaign_id, account_email):
    """Assign an SMTP account to a lead/campaign combination"""
    supabase.table("lead_campaign_accounts").upsert({
        "lead_id": lead_id,
        "campaign_id": campaign_id,
        "smtp_account": account_email
    }).execute()

def get_all_accounts_with_capacity():
    """Get all SMTP accounts with their current usage and capacity"""
    today = date.today().isoformat()
    
    # Get all accounts
    accounts = supabase.table("smtp_accounts").select("*").execute()
    
    accounts_with_capacity = []
    for account in accounts.data:
        # Get today's count for this account
        count_data = supabase.table("daily_email_counts") \
            .select("count") \
            .eq("email_account", account["email"]) \
            .eq("date", today) \
            .execute()
        
        if count_data.data:
            count = count_data.data[0]["count"]
        else:
            count = 0
            
        # Calculate remaining capacity
        remaining = 50 - count
        
        if remaining > 0:
            accounts_with_capacity.append({
                "account": account,
                "sent_today": count,
                "remaining": remaining
            })
    
    # Sort by remaining capacity (descending) to prioritize accounts with most capacity
    accounts_with_capacity.sort(key=lambda x: x["remaining"], reverse=True)
    return accounts_with_capacity

def update_daily_count(email_account, count):
    """Update the daily count for an account"""
    today = date.today().isoformat()
    
    # Check if record exists
    existing = supabase.table("daily_email_counts") \
        .select("id") \
        .eq("email_account", email_account) \
        .eq("date", today) \
        .execute()
    
    if existing.data:
        # Update existing record
        supabase.table("daily_email_counts") \
            .update({"count": count}) \
            .eq("email_account", email_account) \
            .eq("date", today) \
            .execute()
    else:
        # Create new record
        supabase.table("daily_email_counts") \
            .insert({
                "email_account": email_account,
                "date": today,
                "count": count
            }) \
            .execute()

def send_queued():
    print("DEBUG: send_queued function called")
    current_time = datetime.now(timezone.utc)
    print(f"DEBUG: Current time (UTC): {current_time.isoformat()}")
    
    # Get queued emails that are scheduled for now or earlier
    queued = (
        supabase.table("email_queue")
        .select("*")
        .is_("sent_at", "null")
        .lte("scheduled_for", current_time.isoformat())
        .limit(200)
        .execute()
    )

    # Add debug info about the query results
    print(f"DEBUG: Found {len(queued.data)} queued emails")
    
    if not queued.data:
        print("DEBUG: No queued emails ready to send.")
        # Let's check if there are any emails in the queue at all
        all_queued = supabase.table("email_queue").select("*").execute()
        print(f"DEBUG: Total emails in queue: {len(all_queued.data)}")
        
        # Check if there are emails with sent_at null
        unsent = supabase.table("email_queue").select("*").is_("sent_at", "null").execute()
        print(f"DEBUG: Unsent emails in queue: {len(unsent.data)}")
        
        if unsent.data:
            for email in unsent.data:
                print(f"DEBUG: Unsent email - ID: {email['id']}, Scheduled: {email['scheduled_for']}, Now: {current_time.isoformat()}")
        return

    # Get all accounts with capacity
    available_accounts = get_all_accounts_with_capacity()
    
    if not available_accounts:
        print("All accounts have reached their daily limit (50 emails).")
        notify(
            '⚠️ Sending Limit Reached',
            'All SMTP accounts have hit their 50-email daily limit. No emails will be sent until tomorrow.',
            priority='high', tags='warning',
        )
        return
        
    print(f"Found {len(available_accounts)} accounts with capacity")
    
    sent_count = 0
    failed_count = 0
    
    # Distribute emails across available accounts
    account_index = 0
    total_accounts = len(available_accounts)
    
    for q in queued.data:
        # Check if there's an assigned account for this lead/campaign
        assigned_account = get_account_for_lead_campaign(q["lead_id"], q["campaign_id"])
        
        if assigned_account:
            # Use the assigned account if it has capacity
            account_found = None
            for acc in available_accounts:
                if acc["account"]["email"] == assigned_account["email"] and acc["remaining"] > 0:
                    account_found = acc
                    break
            
            if account_found:
                account_data = account_found
                account = account_data["account"]
                current_count = account_data["sent_today"]
            else:
                # Skip this email if the assigned account doesn't have capacity
                print(f"Skipping email for {q['lead_email']} - assigned account has no capacity")
                continue
        else:
            # Use round-robin for emails without an assigned account
            if account_index >= total_accounts:
                account_index = 0
                
            account_data = available_accounts[account_index]
            account = account_data["account"]
            current_count = account_data["sent_today"]
            
            # Assign this account to the lead/campaign for future emails
            assign_account_to_lead_campaign(q["lead_id"], q["campaign_id"], account["email"])
        
        try:
            tracked_body = replace_urls_with_tracking(
                 q["body"], 
                 q["lead_id"], 
                 q["campaign_id"],
                 q["id"]  # email_queue_id
            )

            success = send_email_via_smtp(
                account=account,
                to_email=q["lead_email"],
                subject=q["subject"],
                html_body=tracked_body
            )

            if success:
                # Mark as sent
                update_data = {
                    "sent_at": datetime.now(timezone.utc).isoformat(),
                    "sent_from": account["email"]
                }
                supabase.table("email_queue").update(update_data).match({"id": q["id"]}).execute()
                
                # Update daily count for this account
                new_count = current_count + 1
                update_daily_count(account["email"], new_count)
                
                # Update our local count
                account_data["sent_today"] = new_count
                account_data["remaining"] = 50 - new_count
                
                # If this account is now at capacity, remove it from available accounts
                if new_count >= 50:
                    available_accounts.pop(account_index)
                    total_accounts = len(available_accounts)
                    if total_accounts == 0:
                        print("All accounts have reached their daily limit.")
                        break
                    # Adjust index if we removed the current account
                    if account_index >= total_accounts:
                        account_index = 0
                else:
                    account_index += 1
                
                # If this is an initial email (sequence 0), schedule the first follow-up
                next_sequence = q["sequence"] + 1
                schedule_followup(q, next_sequence, account["email"])
                
                sent_count += 1
            else:
                print(f"Failed to send to {q['lead_email']}")
                failed_count += 1
                account_index += 1  # Move to next account even on failure
                
        except Exception as e:
            print(f"Error sending email to {q['lead_email']}: {str(e)}")
            failed_count += 1
            account_index += 1  # Move to next account on error

    print(f"✅ Sent {sent_count} emails. Failed: {failed_count}")

    # Push notification summary
    if sent_count > 0 or failed_count > 0:
        if failed_count == 0:
            notify(
                f'📧 {sent_count} Emails Sent',
                f'Batch complete — {sent_count} email(s) delivered successfully.',
                priority='low', tags='email',
            )
        else:
            notify(
                f'📧 Batch Done — {failed_count} Failed',
                f'{sent_count} sent, {failed_count} failed. Check logs for details.',
                priority='high', tags='email,warning',
            )

def schedule_followup(q, sequence, account_email):
    """Schedule a follow-up email using the same account"""
    try:
        # Get the follow-up for this campaign and sequence
        follow_up = (
            supabase.table("campaign_followups")
            .select("*")
            .eq("campaign_id", q["campaign_id"])
            .eq("sequence", sequence)
            .execute()
        )
        
        if not follow_up.data:
            return  # No follow-up for this sequence
        
        follow_up = follow_up.data[0]
        # Get lead data
        lead = supabase.table("leads").select("*").eq("id", q["lead_id"]).single().execute()
        
        if lead.data:
            # Calculate send date
            days_delay = follow_up["days_after_previous"]
            send_date = datetime.now(timezone.utc) + timedelta(days=days_delay)
            
            # Render template with lead data
            rendered_subject = render_email_template(follow_up["subject"], lead.data)
            rendered_body = render_email_template(follow_up["body"], lead.data)
            
            # Queue follow-up with the same account
            supabase.table("email_queue").insert({
                "campaign_id": q["campaign_id"],
                "lead_id": q["lead_id"],
                "lead_email": q["lead_email"],
                "subject": rendered_subject,
                "body": rendered_body,
                "sequence": sequence,
                "scheduled_for": send_date.isoformat()
            }).execute()
    except Exception as e:
        print(f"Error scheduling follow-up: {str(e)}")

def render_email_template(template, lead_data):
    """Replace template variables with lead data and preserve whitespace"""
    rendered = template
    
    for key, value in lead_data.items():
        if value is None:
            value = ""
            
        # 1. Replace standard underscores (e.g., {ai_hooks})
        placeholder = "{" + str(key) + "}"
        rendered = rendered.replace(placeholder, str(value))
        
        # 2. Replace version with spaces (e.g., {ai hooks})
        # This makes it user-friendly if they copy CSV headers exactly
        key_with_space = str(key).replace('_', ' ')
        placeholder_space = "{" + key_with_space + "}"
        rendered = rendered.replace(placeholder_space, str(value))
    
    # Preserve line breaks and spaces by converting them to HTML
    rendered = rendered.replace('\n', '<br>')
    rendered = rendered.replace('  ', '&nbsp;&nbsp;')
    
    return rendered

def replace_urls_with_tracking(html_content, lead_id, campaign_id, email_queue_id=None):
    """
    Replace all URLs in HTML content with tracking URLs
    """
    print("=" * 50)
    print(f"DEBUG: replace_urls_with_tracking called")
    print(f"DEBUG: lead_id={lead_id}, campaign_id={campaign_id}, email_queue_id={email_queue_id}")
    print(f"DEBUG: HTML content length: {len(html_content)}")
    
    # Use your actual domain for tracking
    tracking_domain = "https://replyzeai.com/goods"
    print(f"DEBUG: Using tracking_domain = {tracking_domain}")
    
    # Pattern to find href attributes
    pattern = r'href="(.*?)"'
    
    def replace_with_tracking(match):
        original_url = match.group(1)
        print(f"DEBUG: Found URL: {original_url}")
        
        # Skip if it's already a tracking link or mailto link
        if '/track/' in original_url or original_url.startswith('mailto:'):
            print(f"DEBUG: Skipping - already a tracking link or mailto")
            return match.group(0)
            
        # Encode the original URL
        encoded_url = urllib.parse.quote(original_url)
        
        # Build tracking URL
        tracking_url = f"{tracking_domain}/track/{lead_id}/{campaign_id}?url={encoded_url}"
        
        # Add email_queue_id if available
        if email_queue_id:
            tracking_url += f"&eqid={email_queue_id}"
        
        print(f"DEBUG: Created tracking URL: {tracking_url}")
        print(f"DEBUG: Is 'render.com' in tracking_url? {'render.com' in tracking_url}")
        print(f"DEBUG: Is 'replyzeai.com' in tracking_url? {'replyzeai.com' in tracking_url}")
            
        return f'href="{tracking_url}"'
    
    # Replace all URLs
    result = re.sub(pattern, replace_with_tracking, html_content)
    print(f"DEBUG: Result preview (first 1000 chars):")
    print(result[:1000])
    print("=" * 50)
    return result
    
    
# Add these imports to worker.py
import imaplib
import email
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import pdfkit

# ... (Existing Supabase and Encryption code) ...

def generate_pdf_buffer(lead_data):
    """Generates the personalized PDF in memory"""
    full_name = f"{lead_data.get('name', '')} {lead_data.get('last_name', '')}".strip()
    
    # Build the personalized URL params requested
    params = {
        "user_id": lead_data['id'],
        "email": lead_data['email'],
        "full_name": full_name
    }
    encoded_params = urllib.parse.urlencode(params)
    personalized_url = f"https://replyzeai.com/app/auto-register?{encoded_params}"

    # Load HTML and inject the URL
    with open('7days.html', 'r', encoding='utf-8') as f:
        html_content = f.read()
    
    # Replace the trial links in your 7days.html
    html_content = html_content.replace('https://replyzeai.vercel.app/temporary2', personalized_url)

    options = {
        'page-size': 'A4',
        'encoding': "UTF-8",
        'no-outline': None,
        'enable-local-file-access': None
    }
    
    return pdfkit.from_string(html_content, False, options=options)

def send_email_with_pdf(account, to_email, subject, body, pdf_content):
    """Sends an email with the 7daysys.pdf attachment"""
    try:
        smtp_password = aesgcm_decrypt(account["encrypted_smtp_password"])
        msg = MIMEMultipart()
        msg["Subject"] = subject
        msg["From"] = f"{account['display_name']} <{account['email']}>"
        msg["To"] = to_email
        
        msg.attach(MIMEText(body, "html"))
        
        # Attach the PDF
        part = MIMEApplication(pdf_content, Name="7daysys.pdf")
        part['Content-Disposition'] = 'attachment; filename="7daysys.pdf"'
        msg.attach(part)
        
        with smtplib.SMTP(account["smtp_host"], account["smtp_port"]) as server:
            server.starttls()
            server.login(account["smtp_username"], smtp_password)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Failed to send PDF: {e}")
        return False

def check_for_keyword_replies(keyword="ofc"):
    """Scans inboxes for the keyword and sends the PDF"""
    accounts = supabase.table("smtp_accounts").select("*").execute().data
    
    for acc in accounts:
        try:
            # Connect to IMAP
            mail = imaplib.IMAP4_SSL(acc["imap_host"], acc.get("imap_port", 993))
            mail.login(acc["smtp_username"], aesgcm_decrypt(acc["encrypted_smtp_password"]))
            mail.select("inbox")
            
            # Search for unseen messages
            _, data = mail.search(None, 'UNSEEN')
            for num in data[0].split():
                _, msg_data = mail.fetch(num, '(RFC822)')
                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email)
                
                # Get sender and body
                from_email = email.utils.parseaddr(msg['From'])[1].lower()
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_payload(decode=True).decode()
                else:
                    body = msg.get_payload(decode=True).decode()

                # Check for keyword
                if keyword.lower() in body.lower():
                    # Find lead in DB
                    lead = supabase.table("leads").select("*").eq("email", from_email).execute()
                    if lead.data:
                        lead_data = lead.data[0]
                        print(f"Found keyword '{keyword}' from {from_email}. Sending PDF...")
                        
                        pdf_bytes = generate_pdf_buffer(lead_data)
                        success = send_email_with_pdf(
                            acc, 
                            from_email, 
                            "Your Personalized 7-Day Guide", 
                            "Attached is your personalized guide as requested.", 
                            pdf_bytes
                        )
                        if success:
                            # Mark as 'responded' in your DB
                            supabase.table("responded_leads").upsert({"email": from_email, "responded_at": datetime.now(timezone.utc).isoformat()}).execute()
                            
        except Exception as e:
            print(f"Error checking {acc['email']}: {e}")



import imaplib
import email
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import pdfkit

def check_and_reply_with_pdf(keyword="ofc"):
    # Get all connected SMTP accounts
    accounts = supabase.table("smtp_accounts").select("*").execute().data
    
    for acc in accounts:
        try:
            # Connect to IMAP (using same credentials as SMTP)
            mail = imaplib.IMAP4_SSL(acc["imap_host"])
            mail.login(acc["smtp_username"], aesgcm_decrypt(acc["encrypted_smtp_password"]))
            mail.select("inbox")
            
            # Search for UNSEEN (unread) messages
            _, data = mail.search(None, 'UNSEEN')
            for num in data[0].split():
                _, msg_data = mail.fetch(num, '(RFC822)')
                msg = email.message_from_bytes(msg_data[0][1])
                body = ""
                
                # Extract text body
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            body = part.get_payload(decode=True).decode()
                else:
                    body = msg.get_payload(decode=True).decode()

                # If keyword found, generate and send PDF
                if keyword.lower() in body.lower():
                    from_email = email.utils.parseaddr(msg['From'])[1].lower()
                    lead = supabase.table("leads").select("*").eq("email", from_email).execute()
                    
                    if lead.data:
                        print(f"Match found! Sending PDF to {from_email}")
                        # [Add the generate_pdf_buffer and send_email_with_pdf logic here]
                        
        except Exception as e:
            print(f"IMAP Error for {acc['email']}: {e}")
            
        
import pdfkit
import urllib.parse
from email.mime.application import MIMEApplication

# 1. SET THE PATH YOU COPIED HERE
WKHTML_PATH = '/home/wmgtezae/bin/wkhtmltopdf' 
config = pdfkit.configuration(wkhtmltopdf=WKHTML_PATH)

def handle_pdf_reply(lead_data, account, to_email):
    try:
        # 2. Build the personalized URL
        full_name = f"{lead_data.get('name', '')} {lead_data.get('last_name', '')}".strip()
        params = {
            "user_id": lead_data['id'],
            "email": lead_data['email'],
            "full_name": full_name
        }
        encoded_params = urllib.parse.urlencode(params)
        # Your requested URL format
        personalized_url = f"https://replyzeai.com/app/auto-register?{encoded_params}"

        # 3. Read HTML and inject URL
        with open('7days.html', 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Replace the placeholder link in your 7days.html
        html_content = html_content.replace('https://replyzeai.vercel.app/temporary2', personalized_url)

        # 4. Generate PDF using the config
        options = {
            'page-size': 'A4',
            'encoding': "UTF-8",
            'no-outline': None,
            'enable-local-file-access': None # Important for CSS/Images
        }
        
        pdf_bytes = pdfkit.from_string(html_content, False, options=options, configuration=config)

        # 5. Send Email with Attachment
        subject = "Your Personalized 7-Day System"
        body = f"Hi {lead_data.get('name', 'there')}, here is the personalized guide you requested!"
        
        # (Assuming you use a modified version of your send_email function)
        msg = MIMEMultipart()
        msg["Subject"] = subject
        msg["From"] = f"{account['display_name']} <{account['email']}>"
        msg["To"] = to_email
        msg.attach(MIMEText(body, "plain"))

        part = MIMEApplication(pdf_bytes, Name="7daysys.pdf")
        part['Content-Disposition'] = 'attachment; filename="7daysys.pdf"'
        msg.attach(part)

        # ... SMTP send logic ...
        print(f"Successfully sent personalized PDF to {to_email}")

    except Exception as e:
        print(f"Error in PDF flow: {e}")
            
            
if __name__ == "__main__":
    send_queued()
    check_for_keyword_replies(keyword="ofc")
