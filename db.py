import os
import uuid
import psycopg2
from psycopg2 import pool, sql
from psycopg2.extras import RealDictCursor
from datetime import datetime, timezone
import bcrypt

# Database connection pool
db_pool = None

def get_db_connection():
    global db_pool
    if db_pool is None:
        database_url = os.environ.get('DATABASE_URL')
        if not database_url:
            raise RuntimeError("DATABASE_URL environment variable not set")
        db_pool = pool.SimpleConnectionPool(1, 10, database_url)
    return db_pool.getconn()

def put_db_connection(conn):
    db_pool.putconn(conn)

def get_db():
    conn = get_db_connection()
    return PgConnection(conn)

class PgConnection:
    def __init__(self, pg_conn):
        self.pg_conn = pg_conn
        self.cursor = None

    def execute(self, query, params=None):
        if params is None:
            params = ()
        query = query.replace('?', '%s')
        self.cursor = self.pg_conn.cursor()
        self.cursor.execute(query, params)
        return self.cursor

    def commit(self):
        self.pg_conn.commit()

    def close(self):
        if self.cursor:
            self.cursor.close()
        put_db_connection(self.pg_conn)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

def init_db():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Users table with approved column
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('user', 'admin')),
                    postmark_token TEXT UNIQUE,
                    approved BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP
                )
            """)
            # sent_emails
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sent_emails (
                    id TEXT PRIMARY KEY,
                    message_id TEXT,
                    recipient TEXT,
                    from_email TEXT,
                    subject TEXT,
                    status TEXT,
                    sent_at TIMESTAMP,
                    error TEXT,
                    user_id TEXT
                )
            """)
            # send_logs
            cur.execute("""
                CREATE TABLE IF NOT EXISTS send_logs (
                    id TEXT PRIMARY KEY,
                    recipient TEXT,
                    from_email TEXT,
                    subject TEXT,
                    mode TEXT,
                    status TEXT,
                    message_id TEXT,
                    error TEXT,
                    created_at TIMESTAMP,
                    batch_id TEXT,
                    user_id TEXT
                )
            """)
            # bulk_requests
            cur.execute("""
                CREATE TABLE IF NOT EXISTS bulk_requests (
                    id TEXT PRIMARY KEY,
                    bulk_request_id TEXT,
                    from_email TEXT,
                    subject TEXT,
                    total_recipients INTEGER,
                    status TEXT,
                    created_at TIMESTAMP
                )
            """)
            # email_opens
            cur.execute("""
                CREATE TABLE IF NOT EXISTS email_opens (
                    id TEXT PRIMARY KEY,
                    message_id TEXT,
                    recipient TEXT,
                    opened_at TIMESTAMP,
                    user_agent TEXT,
                    platform TEXT,
                    os_family TEXT,
                    client_name TEXT,
                    client_type TEXT,
                    user_id TEXT
                )
            """)
            # email_clicks
            cur.execute("""
                CREATE TABLE IF NOT EXISTS email_clicks (
                    id TEXT PRIMARY KEY,
                    message_id TEXT,
                    recipient TEXT,
                    link TEXT,
                    clicked_at TIMESTAMP,
                    user_agent TEXT,
                    platform TEXT,
                    os_family TEXT,
                    client_name TEXT,
                    client_type TEXT,
                    user_id TEXT
                )
            """)
            # email_bounces
            cur.execute("""
                CREATE TABLE IF NOT EXISTS email_bounces (
                    id TEXT PRIMARY KEY,
                    message_id TEXT,
                    recipient TEXT,
                    bounce_type TEXT,
                    bounce_class INTEGER,
                    description TEXT,
                    details TEXT,
                    bounced_at TIMESTAMP,
                    can_retry BOOLEAN
                )
            """)
            # email_spam_complaints
            cur.execute("""
                CREATE TABLE IF NOT EXISTS email_spam_complaints (
                    id TEXT PRIMARY KEY,
                    message_id TEXT,
                    recipient TEXT,
                    complained_at TIMESTAMP,
                    user_agent TEXT,
                    description TEXT
                )
            """)
            # batch_jobs
            cur.execute("""
                CREATE TABLE IF NOT EXISTS batch_jobs (
                    id TEXT PRIMARY KEY,
                    batch_id TEXT UNIQUE,
                    status TEXT,
                    total_recipients INTEGER,
                    sent INTEGER DEFAULT 0,
                    failed INTEGER DEFAULT 0,
                    duplicates_removed INTEGER DEFAULT 0,
                    subject TEXT,
                    from_email TEXT,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP,
                    user_id TEXT
                )
            """)
            # Add approved column if upgrading from older version
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS approved BOOLEAN DEFAULT FALSE")
        conn.commit()
    finally:
        put_db_connection(conn)

# ---------- Password hashing ----------
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, password_hash):
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

# ---------- User management (with approval) ----------
def create_user(username, email, password, role='user', postmark_token=None):
    conn = get_db_connection()
    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    hashed = hash_password(password)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (id, username, email, password_hash, role, postmark_token, approved, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (user_id, username, email, hashed, role, postmark_token, False, now, now))
            conn.commit()
            return user_id
    except psycopg2.IntegrityError:
        conn.rollback()
        return None
    finally:
        put_db_connection(conn)

def get_user_by_username(username):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        put_db_connection(conn)

def get_user_by_email(email):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE email = %s", (email,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        put_db_connection(conn)

def get_user_by_id(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        put_db_connection(conn)

def get_all_users():
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id, username, email, role, postmark_token, approved, created_at FROM users ORDER BY created_at DESC")
            rows = cur.fetchall()
            return [dict(row) for row in rows]
    finally:
        put_db_connection(conn)

def get_pending_users():
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id, username, email, created_at FROM users WHERE approved = FALSE ORDER BY created_at ASC")
            rows = cur.fetchall()
            return [dict(row) for row in rows]
    finally:
        put_db_connection(conn)

def approve_user(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET approved = TRUE, updated_at = %s WHERE id = %s",
                        (datetime.now(timezone.utc).isoformat(), user_id))
            conn.commit()
    finally:
        put_db_connection(conn)

def reject_user(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()
    finally:
        put_db_connection(conn)

def update_user_password(user_id, new_password):
    conn = get_db_connection()
    hashed = hash_password(new_password)
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET password_hash = %s, updated_at = %s WHERE id = %s",
                        (hashed, datetime.now(timezone.utc).isoformat(), user_id))
            conn.commit()
    finally:
        put_db_connection(conn)

def update_user_role(user_id, new_role):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET role = %s, updated_at = %s WHERE id = %s",
                        (new_role, datetime.now(timezone.utc).isoformat(), user_id))
            conn.commit()
    finally:
        put_db_connection(conn)

def update_user_postmark_token(user_id, token):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET postmark_token = %s, updated_at = %s WHERE id = %s",
                        (token, datetime.now(timezone.utc).isoformat(), user_id))
            conn.commit()
    finally:
        put_db_connection(conn)

def delete_user(user_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()
    finally:
        put_db_connection(conn)

# ---------- Batch job persistence ----------
def create_batch_job(batch_id, status, total_recipients, duplicates_removed, subject, from_email, user_id):
    conn = get_db_connection()
    now = datetime.now(timezone.utc).isoformat()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO batch_jobs (id, batch_id, status, total_recipients, sent, failed, duplicates_removed, subject, from_email, created_at, updated_at, user_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (str(uuid.uuid4()), batch_id, status, total_recipients, 0, 0, duplicates_removed, subject, from_email, now, now, user_id))
            conn.commit()
    finally:
        put_db_connection(conn)

def update_batch_progress(batch_id, sent, failed):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE batch_jobs
                SET sent = %s, failed = %s, updated_at = %s
                WHERE batch_id = %s
            """, (sent, failed, datetime.now(timezone.utc).isoformat(), batch_id))
            conn.commit()
    finally:
        put_db_connection(conn)

def complete_batch_job(batch_id, sent, failed):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE batch_jobs
                SET status = 'completed', sent = %s, failed = %s, updated_at = %s
                WHERE batch_id = %s
            """, (sent, failed, datetime.now(timezone.utc).isoformat(), batch_id))
            conn.commit()
    finally:
        put_db_connection(conn)

def get_all_batch_jobs(limit=50):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT batch_id, status, total_recipients, sent, failed, duplicates_removed, subject, from_email, created_at
                FROM batch_jobs
                ORDER BY created_at DESC
                LIMIT %s
            """, (limit,))
            rows = cur.fetchall()
            return [dict(row) for row in rows]
    finally:
        put_db_connection(conn)

def get_all_batch_jobs_for_user(user_id, limit=50):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT batch_id, status, total_recipients, sent, failed, duplicates_removed, subject, from_email, created_at
                FROM batch_jobs
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT %s
            """, (user_id, limit))
            rows = cur.fetchall()
            return [dict(row) for row in rows]
    finally:
        put_db_connection(conn)

def get_batch_job(batch_id):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM batch_jobs WHERE batch_id = %s", (batch_id,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        put_db_connection(conn)

# ---------- Logging functions ----------
def log_send_attempt(recipient, from_email, subject, mode, status, message_id=None, error=None, batch_id=None, user_id=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO send_logs (id, recipient, from_email, subject, mode, status, message_id, error, created_at, batch_id, user_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (str(uuid.uuid4()), recipient, from_email, subject, mode, status, message_id, error,
                  datetime.now(timezone.utc).isoformat(), batch_id, user_id))
            conn.commit()
    finally:
        put_db_connection(conn)

def log_sent_email(message_id, recipient, from_email, subject, status, error=None, user_id=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO sent_emails (id, message_id, recipient, from_email, subject, status, sent_at, error, user_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (str(uuid.uuid4()), message_id, recipient, from_email, subject, status,
                  datetime.now(timezone.utc).isoformat(), error, user_id))
            conn.commit()
    finally:
        put_db_connection(conn)

def get_recent_sent(limit=50):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM sent_emails ORDER BY sent_at DESC LIMIT %s", (limit,))
            rows = cur.fetchall()
            return [dict(row) for row in rows]
    finally:
        put_db_connection(conn)

def get_recent_sent_for_user(user_id, limit=50):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM sent_emails WHERE user_id = %s ORDER BY sent_at DESC LIMIT %s", (user_id, limit))
            rows = cur.fetchall()
            return [dict(row) for row in rows]
    finally:
        put_db_connection(conn)

def get_send_logs(limit=500):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM send_logs ORDER BY created_at DESC LIMIT %s", (limit,))
            rows = cur.fetchall()
            return [dict(row) for row in rows]
    finally:
        put_db_connection(conn)

def get_send_logs_for_user(user_id, limit=500):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM send_logs WHERE user_id = %s ORDER BY created_at DESC LIMIT %s", (user_id, limit))
            rows = cur.fetchall()
            return [dict(row) for row in rows]
    finally:
        put_db_connection(conn)

def log_bulk_request(bulk_id, from_email, subject, total_recipients):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO bulk_requests (id, bulk_request_id, from_email, subject, total_recipients, status, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (str(uuid.uuid4()), bulk_id, from_email, subject, total_recipients, 'accepted', datetime.now(timezone.utc).isoformat()))
            conn.commit()
    finally:
        put_db_connection(conn)

def log_open(message_id, recipient, opened_at, user_agent=None, platform=None, os_family=None, client_name=None, client_type=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM email_opens WHERE message_id = %s AND recipient = %s", (message_id, recipient))
            if cur.fetchone():
                return
            cur.execute("""
                INSERT INTO email_opens (id, message_id, recipient, opened_at, user_agent, platform, os_family, client_name, client_type)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (str(uuid.uuid4()), message_id, recipient, opened_at, user_agent, platform, os_family, client_name, client_type))
            conn.commit()
    finally:
        put_db_connection(conn)

def log_click(message_id, recipient, link, clicked_at, user_agent=None, platform=None, os_family=None, client_name=None, client_type=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM email_clicks WHERE message_id = %s AND recipient = %s AND link = %s", (message_id, recipient, link))
            if cur.fetchone():
                return
            cur.execute("""
                INSERT INTO email_clicks (id, message_id, recipient, link, clicked_at, user_agent, platform, os_family, client_name, client_type)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (str(uuid.uuid4()), message_id, recipient, link, clicked_at, user_agent, platform, os_family, client_name, client_type))
            conn.commit()
    finally:
        put_db_connection(conn)

def log_bounce(message_id, recipient, bounce_type, bounce_class, description, details, bounced_at, can_retry):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO email_bounces (id, message_id, recipient, bounce_type, bounce_class, description, details, bounced_at, can_retry)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (str(uuid.uuid4()), message_id, recipient, bounce_type, bounce_class, description, details, bounced_at, can_retry))
            conn.commit()
    finally:
        put_db_connection(conn)

def log_spam_complaint(message_id, recipient, complained_at, user_agent=None, description=None):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO email_spam_complaints (id, message_id, recipient, complained_at, user_agent, description)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (str(uuid.uuid4()), message_id, recipient, complained_at, user_agent, description))
            conn.commit()
    finally:
        put_db_connection(conn)

def get_opens_for_batch(batch_id):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT DISTINCT eo.recipient, eo.opened_at, eo.user_agent
                FROM email_opens eo
                JOIN send_logs sl ON eo.message_id = sl.message_id
                WHERE sl.batch_id = %s AND sl.status = 'sent'
                ORDER BY eo.opened_at DESC
            """, (batch_id,))
            rows = cur.fetchall()
            return [dict(row) for row in rows]
    finally:
        put_db_connection(conn)

def get_clicks_for_batch(batch_id):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT DISTINCT ec.recipient, ec.link, ec.clicked_at, ec.user_agent
                FROM email_clicks ec
                JOIN send_logs sl ON ec.message_id = sl.message_id
                WHERE sl.batch_id = %s AND sl.status = 'sent'
                ORDER BY ec.clicked_at DESC
            """, (batch_id,))
            rows = cur.fetchall()
            return [dict(row) for row in rows]
    finally:
        put_db_connection(conn)

def get_bounces_and_complaints(limit=500):
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT recipient, bounce_type, description, details, bounced_at, message_id
                FROM email_bounces
                ORDER BY bounced_at DESC LIMIT %s
            """, (limit,))
            bounces = cur.fetchall()
            cur.execute("""
                SELECT recipient, complained_at, description, message_id
                FROM email_spam_complaints
                ORDER BY complained_at DESC LIMIT %s
            """, (limit,))
            complaints = cur.fetchall()
            return [dict(row) for row in bounces], [dict(row) for row in complaints]
    finally:
        put_db_connection(conn)

def get_batch_counters(batch_id):
    opens = get_opens_for_batch(batch_id)
    clicks = get_clicks_for_batch(batch_id)
    return len(opens), len(clicks)

# Initialize database tables (idempotent)
init_db()
