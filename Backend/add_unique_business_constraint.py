
from db import get_db_connection

conn = get_db_connection()
cur = conn.cursor()

try:
    cur.execute("""
        ALTER TABLE business_registrations
        ADD CONSTRAINT unique_business_email
        UNIQUE (email, business_name);
    """)
    conn.commit()
    print("✅ UNIQUE constraint added successfully")

except Exception as e:
    conn.rollback()
    print("❌ Error:", e)

finally:
    cur.close()
    conn.close()
