from dotenv import load_dotenv
import os

# Load .env file
load_dotenv()

from db import get_db_connection

conn = get_db_connection()
cur = conn.cursor()

cur.execute("""
ALTER TABLE users
ADD COLUMN name VARCHAR(100);
""")

conn.commit()
cur.close()
conn.close()

print("✅ name column added successfully")


