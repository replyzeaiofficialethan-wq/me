import os
from supabase import create_client

SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_SERVICE_ROLE_KEY')

if not SUPABASE_URL or not SUPABASE_KEY:
    print("Missing Supabase credentials. Migration script cannot run.")
    exit(1)

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# Note: As Jules mentioned, running raw SQL via the client isn't directly supported
# without an RPC or a specific extension. I will provide the SQL to be run.
# However, I can check if columns exist using a dummy select if needed.

sql_migration = """
-- Add columns to leads for belief-test framework
ALTER TABLE public.leads
ADD COLUMN IF NOT EXISTS belief_variant TEXT,
ADD COLUMN IF NOT EXISTS belief_assigned_at TIMESTAMPTZ;
"""

if __name__ == "__main__":
    print("Execute the following SQL in the Supabase SQL Editor:\n")
    print(sql_migration)
