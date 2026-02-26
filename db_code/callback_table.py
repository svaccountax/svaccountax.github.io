import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()
# DB
DATABASE_URL = os.getenv("DATABASE_URL")


if not DATABASE_URL:
    raise Exception("DATABASE_URL not set")

conn = psycopg2.connect(DATABASE_URL)
cursor = conn.cursor()

create_table_query = """
CREATE TABLE IF NOT EXISTS callback_requests (
    id SERIAL PRIMARY KEY,
    phone VARCHAR(20),
    email VARCHAR(255),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
);
"""

cursor.execute(create_table_query)
conn.commit()

cursor.close()
conn.close()

print("✅ callback_table created successfully")
