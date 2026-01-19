import psycopg2
from urllib.parse import urlparse
import sys
import os

# 1. Manually set your DB URL here if .env fails, or read from environment
# Based on your previous logs, it looks like:
# DATABASE_URL="postgresql+psycopg2://postgres:5432@127.0.0.1:5432/websec_db"
# But let's try to read .env first
db_url = "postgresql://postgres:postgres@127.0.0.1:5432/websec_db"

try:
    with open(".env", "r") as f:
        for line in f:
            if line.startswith("DATABASE_URL="):
                clean_line = line.strip().split("=", 1)[1].strip('"').strip("'")
                # Remove the +psycopg2 driver part for standard connection
                db_url = clean_line.replace("+psycopg2", "")
except FileNotFoundError:
    print("⚠️ .env file not found, trying default URL...")

# 2. Connect and Truncate
try:
    print(f"Connecting to database...")
    result = urlparse(db_url)
    username = result.username
    password = result.password
    database = result.path[1:]
    port = result.port or 5432
    host = result.hostname

    conn = psycopg2.connect(
        dbname=database,
        user=username,
        password=password,
        host=host,
        port=port
    )
    conn.autocommit = True
    
    with conn.cursor() as cur:
        print("🧹 Wiping all data rows (keeping tables)...")
        # This deletes data but keeps the table structure
        cur.execute("TRUNCATE TABLE users, targets, scans, findings, pdf_reports RESTART IDENTITY CASCADE;")
        print("✅ Database is fresh and empty!")

    conn.close()

except Exception as e:
    print(f"\n❌ Error: {e}")
    print("Ensure Postgres is running and the password is correct.")