import psycopg2
from urllib.parse import urlparse
import sys

# 1. Read the database URL directly from your .env file
db_url = ""
try:
    with open(".env", "r") as f:
        for line in f:
            if line.startswith("DATABASE_URL="):
                # Clean up the line to get just the URL
                db_url = line.strip().split("=", 1)[1].strip('"').strip("'")
except FileNotFoundError:
    print("Error: Could not find .env file!")
    sys.exit(1)

# 2. Parse the URL to get login details
try:
    result = urlparse(db_url)
    username = result.username
    password = result.password
    database = result.path[1:]  # remove the leading slash
    hostname = result.hostname
    port = result.port
except Exception as e:
    print(f"Error parsing URL: {e}")
    sys.exit(1)

print(f"Connecting to database '{database}' as user '{username}'...")

# 3. Connect and Wipe Everything
try:
    conn = psycopg2.connect(
        dbname=database,
        user=username,
        password=password,
        host=hostname,
        port=port
    )
    conn.autocommit = True  # Required to drop schemas
    
    with conn.cursor() as cur:
        print("💥 Dropping all tables (Schema public)...")
        cur.execute("DROP SCHEMA public CASCADE;")
        print("✅ Old tables deleted.")
        
        print("✨ Recreating fresh schema...")
        cur.execute("CREATE SCHEMA public;")
        print("✅ Database is now 100% empty and ready.")
        
    conn.close()

except Exception as e:
    print("\n❌ ERROR: Could not connect to the database.")
    print(f"Details: {e}")
    print("\nTroubleshooting:")
    print("1. Make sure your password in .env is correct.")
    print("2. Make sure PostgreSQL is running.")