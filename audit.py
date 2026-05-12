import os
import json
import requests
from datetime import datetime, timezone, timedelta
from supabase import create_client

# ── Supabase Setup ──────────────────────────────────────────────────────────
SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_SERVICE_ROLE_KEY')
supabase     = create_client(SUPABASE_URL, SUPABASE_KEY)

# ── Groq Setup ──────────────────────────────────────────────────────────────
def get_groq_completion(prompt, system_prompt, model="llama-3.3-70b-versatile", retry_count=0):
    key = os.environ.get('GROQ_API_KEY')
    if not key:
        return "GROQ_API_KEY not configured."

    # Rate limit buffer for free tier
    time.sleep(2)

    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.2
            },
            timeout=60
        )
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"]

        if resp.status_code == 429 and retry_count < 3:
            # Exponential backoff
            wait_time = (2 ** retry_count) * 15
            print(f"Rate limited. Waiting {wait_time}s before retry {retry_count + 1}...")
            time.sleep(wait_time)
            return get_groq_completion(prompt, system_prompt, model, retry_count + 1)

        return f"Error: {resp.status_code} - {resp.text}"
    except Exception as e:
        return f"Exception: {str(e)}"

# ── Data Fetching ───────────────────────────────────────────────────────────
def fetch_audit_data():
    data = {}

    # Selectively sample leads to find low-conversion patterns without hitting token limits
    # Focus on diversity of brokerage and city
    leads_res = supabase.table("leads").select("city,brokerage,responded,outreach_status").limit(300).execute()
    data['leads_summary'] = leads_res.data

    # Recent responses - focus on the content
    responses_res = supabase.table("responded_leads").select("intent,raw_reply").order("responded_at", desc=True).limit(20).execute()
    data['recent_responses'] = responses_res.data

    # Recent decisions
    decisions_res = supabase.table("processed_replies").select("intent,reasoning,raw_reply").order("processed_at", desc=True).limit(20).execute()
    data['recent_decisions'] = decisions_res.data

    # Code snippets
    try:
        with open("check_replies.py", "r") as f:
            data['code_check_replies'] = f.read()[:5000] # Cap it
        with open("worker.py", "r") as f:
            data['code_worker'] = f.read()[:3000]
    except:
        data['code_error'] = "Could not read source files."

    return data

# ── Agent 1: Data Analyst ───────────────────────────────────────────────────
def run_data_analyst(audit_data):
    system_prompt = """
    You are a Data Analyst Agent for ReplyzeAI. Your job is to look at lead segments and conversion stats.
    Find patterns: Are certain brokerages or cities responding better?
    Is the 'outreach_status' stuck for many leads?
    Conversion is defined as someone saying 'YES' to a free trial.
    """

    leads_json = json.dumps(audit_data['leads_summary'])
    prompt = f"Analyze these lead segments and outreach statuses for patterns of success or failure:\n\n{leads_json}"

    return get_groq_completion(prompt, system_prompt, model="llama-3.1-8b-instant")

# ── Agent 2: Sentiment Specialist ───────────────────────────────────────────
def run_sentiment_specialist(audit_data):
    system_prompt = """
    You are a Sentiment Specialist Agent. Your job is to read actual replies from real estate agents.
    Identify:
    - Why are they saying no? (Objections)
    - Are they confused by the question 'who replies?'
    - Is the tone of our auto-replies matching their energy?
    - Where is the friction in the conversation?
    """

    responses_json = json.dumps(audit_data['recent_responses'])
    decisions_json = json.dumps(audit_data['recent_decisions'])
    prompt = f"Read these actual replies and our AI's reasoning. Identify common objections and friction points:\n\nResponses:\n{responses_json}\n\nDecisions/Reasoning:\n{decisions_json}"

    return get_groq_completion(prompt, system_prompt, model="llama-3.1-8b-instant")

# ── Agent 3: System Architect ───────────────────────────────────────────────
def run_system_architect(audit_data):
    system_prompt = """
    You are a System Architect Agent. Your job is to review the code logic and funnel structure.
    Look at the 'check_replies.py' logic and templates.
    Is the transition from 'who replies?' to 'free trial' too fast?
    Are there bugs in how we handle intents?
    """

    code = audit_data.get('code_check_replies', '')
    prompt = f"Review this code logic for the auto-reply system. Find misalignments with a high-converting sales funnel:\n\n{code}"

    return get_groq_completion(prompt, system_prompt)

# ── Agent 4: Lead Auditor (Executive Summary) ──────────────────────────────
def run_lead_auditor(analyst, sentiment, architect):
    system_prompt = """
    You are the Lead Conversion Auditor for ReplyzeAI.
    Your job is to synthesize the findings from the Data Analyst, Sentiment Specialist, and System Architect.
    Produce a concise, hard-hitting executive summary.
    Identify the #1 reason for low conversion and give 3 immediate action steps.
    """

    prompt = f"""
    Synthesize these findings:

    DATA ANALYST:
    {analyst}

    SENTIMENT SPECIALIST:
    {sentiment}

    SYSTEM ARCHITECT:
    {architect}
    """

    return get_groq_completion(prompt, system_prompt)

# ── Main Audit Runner ───────────────────────────────────────────────────────
def generate_audit_report(save_to_file=True):
    print("🚀 Starting Conversion Audit...")
    audit_data = fetch_audit_data()

    analyst_output = run_data_analyst(audit_data)
    time.sleep(5) # Rate limit gap
    sentiment_output = run_sentiment_specialist(audit_data)
    time.sleep(5)
    architect_output = run_system_architect(audit_data)
    time.sleep(5)
    summary_output = run_lead_auditor(analyst_output, sentiment_output, architect_output)

    # Aggregate Report
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ReplyzeAI Conversion Audit</title>
        <style>
            body {{ font-family: sans-serif; line-height: 1.6; color: #333; max-width: 1000px; margin: auto; padding: 20px; background: #f4f7f6; }}
            .report-card {{ background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 30px; }}
            h1 {{ color: #0a192f; border-bottom: 3px solid #64ffda; padding-bottom: 10px; }}
            h2 {{ color: #112240; margin-top: 0; }}
            .agent-name {{ font-weight: bold; color: #64ffda; background: #0a192f; padding: 5px 10px; border-radius: 4px; display: inline-block; margin-bottom: 15px; }}
            .content {{ white-space: pre-wrap; }}
            .timestamp {{ font-size: 0.9em; color: #888; text-align: right; }}
        </style>
    </head>
    <body>
        <h1>ReplyzeAI Conversion Audit Report</h1>
        <div class="timestamp">Generated on: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC</div>

        <div class="report-card">
            <div class="agent-name">📊 Data Analyst Agent</div>
            <div class="content">{analyst_output}</div>
        </div>

        <div class="report-card">
            <div class="agent-name">🧠 Sentiment Specialist Agent</div>
            <div class="content">{sentiment_output}</div>
        </div>

        <div class="report-card">
            <div class="agent-name">🏗️ System Architect Agent</div>
            <div class="content">{architect_output}</div>
        </div>

        <div class="report-card" style="border-left: 10px solid #64ffda;">
            <h2>🎯 Executive Summary & Action Plan</h2>
            <div class="agent-name">🏆 Lead Auditor Agent</div>
            <div class="content">{summary_output}</div>
        </div>
    </body>
    </html>
    """

    if save_to_file:
        with open("audit_report.html", "w") as f:
            f.write(html_content)
        print("✅ Audit Report generated: audit_report.html")

    return html_content

if __name__ == "__main__":
    generate_audit_report()
