import os
from supabase import create_client

SUPABASE_URL = os.environ['SUPABASE_URL']
SUPABASE_KEY = os.environ['SUPABASE_SERVICE_ROLE_KEY']
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

def run_sql(sql):
    # Supabase client doesn't directly support running arbitrary SQL.
    # We usually use the SQL editor in the dashboard.
    # However, sometimes we can use the 'query' method if available or rpc.
    # Since I cannot easily run raw SQL here, I will document the changes
    # and try to check if columns exist.
    print(f"To be run in Supabase SQL Editor:\n\n{sql}")

sql_migration = """
-- Add columns to email_queue
ALTER TABLE public.email_queue
ADD COLUMN IF NOT EXISTS thread_id TEXT,
ADD COLUMN IF NOT EXISTS in_reply_to TEXT,
ADD COLUMN IF NOT EXISTS "references" TEXT;

-- Add columns to leads
ALTER TABLE public.leads
ADD COLUMN IF NOT EXISTS reply_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS conversation_stage TEXT,
ADD COLUMN IF NOT EXISTS product_introduced BOOLEAN DEFAULT FALSE,
ADD COLUMN IF NOT EXISTS last_intent TEXT,
ADD COLUMN IF NOT EXISTS last_auto_reply_at TIMESTAMPTZ;
"""

if __name__ == "__main__":
    print(sql_migration)
