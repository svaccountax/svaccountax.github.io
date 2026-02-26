
from dotenv import load_dotenv
load_dotenv()

from db import get_db_connection

conn = get_db_connection()
cur = conn.cursor()

cur.execute("""
ALTER TABLE users
ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
""")

conn.commit()
cur.close()
conn.close()

print("✅ created_at column added")
