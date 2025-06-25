from supabase import create_client, Client
import os

_supabase: Client | None = None

def get_client() -> Client:
    global _supabase
    if _supabase is None:
        url = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_KEY")
        if not url or not key:
            raise RuntimeError("SUPABASE_URL e SUPABASE_KEY não configurados no ambiente")
        _supabase = create_client(url, key)
    return _supabase 
