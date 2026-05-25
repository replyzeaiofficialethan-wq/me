import os
from supabase import create_client

SUPABASE_URL = os.environ['SUPABASE_URL']
SUPABASE_KEY = os.environ['SUPABASE_SERVICE_ROLE_KEY']
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

try:
    res = supabase.table("email_queue").select("thread_id").limit(1).execute()
    print("email_queue.thread_id exists")
except Exception as e:
    print(f"email_queue.thread_id missing: {e}")

try:
    res = supabase.table("leads").select("reply_count").limit(1).execute()
    print("leads.reply_count exists")
except Exception as e:
    print(f"leads.reply_count missing: {e}")
