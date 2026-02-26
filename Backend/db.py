
import psycopg2
import os
from psycopg2.pool import ThreadedConnectionPool
from psycopg2 import OperationalError, InterfaceError
import time

_db_pool = None
_pool_unavailable_until = 0.0
_pool_dsn = None


def _candidate_db_urls():
    # Prefer local DB for this machine, then shared/cloud DB.
    urls = []
    for key in ("LOCAL_DATABASE_URL", "DATABASE_URL", "NEON_DATABASE_URL"):
        val = (os.getenv(key) or "").strip()
        if val and val not in urls:
            urls.append(val)
    return urls


def _get_pool():
    global _db_pool, _pool_unavailable_until, _pool_dsn

    now = time.time()
    if now < _pool_unavailable_until:
        raise OperationalError("Database temporarily unavailable; retry shortly")

    if _db_pool is None:
        db_urls = _candidate_db_urls()
        if not db_urls:
            raise RuntimeError("Set LOCAL_DATABASE_URL or DATABASE_URL")

        last_error = None
        for db_url in db_urls:
            try:
                _db_pool = ThreadedConnectionPool(
                    minconn=1,
                    maxconn=10,
                    dsn=db_url,
                    connect_timeout=2,
                    options="-c statement_timeout=3000"
                )
                _pool_dsn = db_url
                break
            except Exception as exc:
                last_error = exc
                _db_pool = None
                _pool_dsn = None

        if _db_pool is None:
            _pool_unavailable_until = now + 5
            raise last_error if last_error else OperationalError("Unable to initialize DB pool")
    return _db_pool

def get_db_connection():
    pool = _get_pool()
    last_error = None

    for _ in range(2):
        conn = pool.getconn()
        try:
            # Validate borrowed pooled connection; reconnect if backend dropped it.
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
            return conn
        except (OperationalError, InterfaceError) as exc:
            last_error = exc
            try:
                pool.putconn(conn, close=True)
            except Exception:
                pass
        except Exception:
            # Non-connectivity issue: return connection for normal error handling.
            return conn

    raise last_error if last_error else RuntimeError("Unable to obtain a healthy DB connection")


def release_db_connection(conn):
    if conn is None:
        return
    pool = _get_pool()
    try:
        if getattr(conn, "closed", 0):
            return
        if conn.status != psycopg2.extensions.STATUS_READY:
            conn.rollback()
        pool.putconn(conn)
    except (OperationalError, InterfaceError):
        try:
            pool.putconn(conn, close=True)
        except Exception:
            pass
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
