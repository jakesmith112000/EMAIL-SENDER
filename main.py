import os
import time
import json
import re
import csv
import uuid
import requests
from io import StringIO
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, make_response, session, redirect, url_for
from flask_cors import CORS
from dotenv import load_dotenv
import db

load_dotenv()

app = Flask(__name__, static_folder='frontend', static_url_path='')
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
CORS(app, supports_credentials=True)

# Global Postmark token (only used for admin stats endpoint)
GLOBAL_POSTMARK_TOKEN = os.environ.get('POSTMARK_SERVER_TOKEN')
if not GLOBAL_POSTMARK_TOKEN:
    raise RuntimeError("POSTMARK_SERVER_TOKEN not set in .env (required for admin stats)")

POSTMARK_API_URL = 'https://api.postmarkapp.com'

# ----------------------------------------------------------------------
# Authentication decorators
# ----------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        user = db.get_user_by_id(session['user_id'])
        if not user or user.get('role') != 'admin':
            return jsonify({'error': 'Admin privileges required'}), 403
        return f(*args, **kwargs)
    return decorated_function

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def sanitize_json_string(s):
    if not isinstance(s, str):
        return s
    s = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', s)
    return s

def clean_payload(payload):
    if isinstance(payload, dict):
        return {k: clean_payload(v) for k, v in payload.items()}
    elif isinstance(payload, list):
        return [clean_payload(item) for item in payload]
    elif isinstance(payload, str):
        return sanitize_json_string(payload)
    else:
        return payload

def deduplicate_recipients(recipients):
    seen = set()
    unique = []
    for email in recipients:
        email_clean = email.strip()
        if not email_clean:
            continue
        email_lower = email_clean.lower()
        if email_lower not in seen:
            seen.add(email_lower)
            unique.append(email_clean)
    return unique

def check_batch_ownership(batch_id):
    """
    Returns (job, error_response, status_code)
    - On success: (job, None, None)
    - On error: (None, error_response, status_code)
    """
    job = db.get_batch_job(batch_id)
    if not job:
        return None, jsonify({'error': 'Batch not found'}), 404
    user = db.get_user_by_id(session['user_id'])
    if user['role'] != 'admin' and job.get('user_id') != session['user_id']:
        return None, jsonify({'error': 'Access denied'}), 403
    return job, None, None

# ----------------------------------------------------------------------
# Authentication endpoints
# ----------------------------------------------------------------------
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    
    if not username or not email or not password:
        return jsonify({'error': 'Username, email and password required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400
    
    user_id = db.create_user(username, email, password, role='user')
    if not user_id:
        return jsonify({'error': 'Username or email already exists'}), 409
    
    return jsonify({'success': True, 'message': 'Registration successful. Please wait for admin approval.'}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    identifier = data.get('username', '').strip()
    password = data.get('password', '')
    
    user = db.get_user_by_username(identifier)
    if not user:
        user = db.get_user_by_email(identifier)
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not db.verify_password(password, user['password_hash']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Check if account is approved
    if not user.get('approved', False):
        return jsonify({'error': 'Account not approved. Please wait for admin approval.'}), 403
    
    session['user_id'] = user['id']
    session['role'] = user['role']
    return jsonify({
        'success': True,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role']
        }
    }), 200

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True}), 200

@app.route('/api/auth/me', methods=['GET'])
def me():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    user = db.get_user_by_id(session['user_id'])
    if not user:
        session.clear()
        return jsonify({'error': 'User not found'}), 401
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'role': user['role'],
        'has_postmark_token': user.get('postmark_token') is not None
    }), 200

@app.route('/api/user/password', methods=['PUT'])
@login_required
def change_password():
    data = request.json
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({'error': 'Current and new password required'}), 400
    if len(new_password) < 6:
        return jsonify({'error': 'New password must be at least 6 characters'}), 400
    
    user = db.get_user_by_id(session['user_id'])
    if not db.verify_password(current_password, user['password_hash']):
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    db.update_user_password(session['user_id'], new_password)
    return jsonify({'success': True}), 200

# ----------------------------------------------------------------------
# Admin user management (with approval system)
# ----------------------------------------------------------------------
@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_list_users():
    users = db.get_all_users()
    for u in users:
        u.pop('password_hash', None)
        if u.get('postmark_token'):
            u['postmark_token_masked'] = u['postmark_token'][:8] + '...' + u['postmark_token'][-4:]
    return jsonify(users), 200

@app.route('/api/admin/users', methods=['POST'])
@admin_required
def admin_create_user():
    data = request.json
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password = data.get('password', '')
    role = data.get('role', 'user')
    postmark_token = data.get('postmark_token', '').strip() or None
    
    if not username or not email or not password:
        return jsonify({'error': 'Username, email and password required'}), 400
    if role not in ('user', 'admin'):
        return jsonify({'error': 'Invalid role'}), 400
    
    user_id = db.create_user(username, email, password, role, postmark_token)
    if not user_id:
        return jsonify({'error': 'Username, email or token already exists'}), 409
    return jsonify({'success': True, 'user_id': user_id}), 201

@app.route('/api/admin/users/<user_id>', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    db.delete_user(user_id)
    return jsonify({'success': True}), 200

@app.route('/api/admin/users/<user_id>/role', methods=['PUT'])
@admin_required
def admin_update_role(user_id):
    data = request.json
    new_role = data.get('role')
    if new_role not in ('user', 'admin'):
        return jsonify({'error': 'Invalid role'}), 400
    db.update_user_role(user_id, new_role)
    return jsonify({'success': True}), 200

@app.route('/api/admin/users/<user_id>/password', methods=['PUT'])
@admin_required
def admin_reset_password(user_id):
    data = request.json
    new_password = data.get('new_password')
    if not new_password or len(new_password) < 6:
        return jsonify({'error': 'New password must be at least 6 characters'}), 400
    db.update_user_password(user_id, new_password)
    return jsonify({'success': True}), 200

@app.route('/api/admin/users/<user_id>/token', methods=['PUT'])
@admin_required
def admin_update_token(user_id):
    data = request.json
    token = data.get('postmark_token', '').strip() or None
    db.update_user_postmark_token(user_id, token)
    return jsonify({'success': True}), 200

# ----- Admin approval endpoints -----
@app.route('/api/admin/users/pending', methods=['GET'])
@admin_required
def admin_pending_users():
    users = db.get_pending_users()
    return jsonify(users), 200

@app.route('/api/admin/users/<user_id>/approve', methods=['POST'])
@admin_required
def admin_approve_user(user_id):
    db.approve_user(user_id)
    return jsonify({'success': True}), 200

@app.route('/api/admin/users/<user_id>/reject', methods=['DELETE'])
@admin_required
def admin_reject_user(user_id):
    if user_id == session['user_id']:
        return jsonify({'error': 'Cannot reject your own account'}), 400
    db.reject_user(user_id)
    return jsonify({'success': True}), 200

# ----------------------------------------------------------------------
# Single Email
# ----------------------------------------------------------------------
@app.route('/api/send', methods=['POST'])
@login_required
def send_single():
    user = db.get_user_by_id(session['user_id'])
    if not user.get('postmark_token'):
        return jsonify({'error': 'No Postmark token assigned. Contact admin.'}), 403
    
    data = request.json
    required = ['FromEmail', 'Subject', 'To']
    if not all(data.get(f) for f in required):
        return jsonify({'error': 'Missing FromEmail, Subject, or To'}), 400

    from_email = data['FromEmail']
    from_name = data.get('FromName', '')
    from_address = f"{from_name} <{from_email}>" if from_name else from_email

    payload = {
        'From': from_address,
        'To': data['To'],
        'Subject': sanitize_json_string(data['Subject']),
        'HtmlBody': sanitize_json_string(data.get('HtmlBody', '')),
        'TextBody': sanitize_json_string(data.get('TextBody', '')),
        'TrackOpens': True,
        'TrackLinks': 'HtmlAndText'
    }
    if 'Attachments' in data and data['Attachments']:
        payload['Attachments'] = data['Attachments']

    payload = clean_payload(payload)

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'X-Postmark-Server-Token': user['postmark_token']
    }

    try:
        resp = requests.post(f'{POSTMARK_API_URL}/email', headers=headers, json=payload, timeout=30)
        result = resp.json()
        if resp.status_code == 200:
            message_id = result.get('MessageID')
            db.log_send_attempt(data['To'], from_email, data['Subject'], 'single', 'sent', message_id, user_id=session['user_id'])
            db.log_sent_email(message_id, data['To'], from_email, data['Subject'], 'sent', user_id=session['user_id'])
            return jsonify({'success': True, 'message_id': message_id}), 200
        else:
            error_msg = result.get('Message', 'Unknown error')
            db.log_send_attempt(data['To'], from_email, data['Subject'], 'single', 'failed', error=error_msg, user_id=session['user_id'])
            db.log_sent_email(None, data['To'], from_email, data['Subject'], 'failed', error_msg, user_id=session['user_id'])
            return jsonify({'success': False, 'error': error_msg}), resp.status_code
    except Exception as e:
        db.log_send_attempt(data['To'], from_email, data['Subject'], 'single', 'failed', error=str(e), user_id=session['user_id'])
        db.log_sent_email(None, data['To'], from_email, data['Subject'], 'failed', str(e), user_id=session['user_id'])
        return jsonify({'success': False, 'error': str(e)}), 500

# ----------------------------------------------------------------------
# Batch API
# ----------------------------------------------------------------------
@app.route('/api/send/batch', methods=['POST'])
@login_required
def send_batch():
    user = db.get_user_by_id(session['user_id'])
    if not user.get('postmark_token'):
        return jsonify({'error': 'No Postmark token assigned. Contact admin.'}), 403
    
    data = request.json
    from_email = data.get('FromEmail')
    from_name = data.get('FromName', '')
    recipients_raw = data.get('Recipients', [])
    subject = data.get('Subject', '')
    html_body = data.get('HtmlBody', '')
    text_body = data.get('TextBody', '')
    attachments = data.get('Attachments', [])
    message_stream = data.get('MessageStream', 'outbound')

    if not from_email or not recipients_raw or not subject:
        return jsonify({'error': 'Missing FromEmail, Recipients, or Subject'}), 400

    original_count = len(recipients_raw)
    recipients = deduplicate_recipients(recipients_raw)
    duplicates_removed = original_count - len(recipients)

    batch_id = str(uuid.uuid4())
    db.create_batch_job(batch_id, 'processing', len(recipients), duplicates_removed, subject, from_email, session['user_id'])

    import threading
    thread = threading.Thread(target=process_batch, args=(
        batch_id, from_email, from_name, recipients, subject, html_body, text_body,
        attachments, message_stream, user['postmark_token'], session['user_id']
    ))
    thread.start()

    return jsonify({
        'success': True,
        'batch_id': batch_id,
        'total_recipients': len(recipients),
        'duplicates_removed': duplicates_removed
    }), 200

def process_batch(batch_id, from_email, from_name, recipients, subject, html_body, text_body, attachments, message_stream, postmark_token, user_id):
    chunk_size = 500
    from_address = f"{from_name} <{from_email}>" if from_name else from_email
    total_sent = 0
    total_failed = 0

    subject = sanitize_json_string(subject)
    html_body = sanitize_json_string(html_body)
    text_body = sanitize_json_string(text_body)

    for i in range(0, len(recipients), chunk_size):
        chunk = recipients[i:i+chunk_size]
        messages = []
        for recipient in chunk:
            msg = {
                'From': from_address,
                'To': recipient.strip(),
                'Subject': subject,
                'HtmlBody': html_body,
                'TextBody': text_body,
                'MessageStream': message_stream,
                'TrackOpens': True,
                'TrackLinks': 'HtmlAndText'
            }
            if attachments:
                msg['Attachments'] = attachments
            messages.append(msg)

        messages = clean_payload(messages)
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Postmark-Server-Token': postmark_token
        }

        for attempt in range(1, 4):
            try:
                resp = requests.post(f'{POSTMARK_API_URL}/email/batch', headers=headers, json=messages, timeout=60)
                if resp.status_code == 200:
                    result = resp.json()
                    for idx, msg_result in enumerate(result):
                        recipient = chunk[idx]
                        if msg_result.get('ErrorCode') == 0:
                            message_id = msg_result.get('MessageID')
                            db.log_send_attempt(recipient, from_email, subject, 'batch', 'sent', message_id, batch_id=batch_id, user_id=user_id)
                            db.log_sent_email(message_id, recipient, from_email, subject, 'sent', user_id=user_id)
                            total_sent += 1
                        else:
                            error_msg = msg_result.get('Message', 'Unknown error')
                            db.log_send_attempt(recipient, from_email, subject, 'batch', 'failed', error=error_msg, batch_id=batch_id, user_id=user_id)
                            db.log_sent_email(None, recipient, from_email, subject, 'failed', error_msg, user_id=user_id)
                            total_failed += 1
                    db.update_batch_progress(batch_id, total_sent, total_failed)
                    break
                elif resp.status_code >= 500:
                    if attempt < 3:
                        time.sleep(2 ** attempt)
                        continue
                    else:
                        error_msg = f"Postmark server error {resp.status_code}: {resp.text}"
                        for recipient in chunk:
                            db.log_send_attempt(recipient, from_email, subject, 'batch', 'failed', error=error_msg, batch_id=batch_id, user_id=user_id)
                            db.log_sent_email(None, recipient, from_email, subject, 'failed', error_msg, user_id=user_id)
                            total_failed += 1
                        db.update_batch_progress(batch_id, total_sent, total_failed)
                        break
                else:
                    error_msg = resp.json().get('Message', f'HTTP {resp.status_code}')
                    for recipient in chunk:
                        db.log_send_attempt(recipient, from_email, subject, 'batch', 'failed', error=error_msg, batch_id=batch_id, user_id=user_id)
                        db.log_sent_email(None, recipient, from_email, subject, 'failed', error_msg, user_id=user_id)
                        total_failed += 1
                    db.update_batch_progress(batch_id, total_sent, total_failed)
                    break
            except Exception as e:
                if attempt < 3:
                    time.sleep(2 ** attempt)
                    continue
                else:
                    error_msg = f"Error after 3 attempts: {str(e)}"
                    for recipient in chunk:
                        db.log_send_attempt(recipient, from_email, subject, 'batch', 'failed', error=error_msg, batch_id=batch_id, user_id=user_id)
                        db.log_sent_email(None, recipient, from_email, subject, 'failed', error_msg, user_id=user_id)
                        total_failed += 1
                    db.update_batch_progress(batch_id, total_sent, total_failed)
                    break

    db.complete_batch_job(batch_id, total_sent, total_failed)

@app.route('/api/batch/progress/<batch_id>', methods=['GET'])
@login_required
def get_batch_progress(batch_id):
    job, err_resp, status = check_batch_ownership(batch_id)
    if err_resp:
        return err_resp, status
    opens_count, clicks_count = db.get_batch_counters(batch_id)
    return jsonify({
        'batch_id': batch_id,
        'status': job['status'],
        'total': job['total_recipients'],
        'sent': job['sent'],
        'failed': job['failed'],
        'duplicates_removed': job.get('duplicates_removed', 0),
        'subject': job.get('subject', ''),
        'from_email': job.get('from_email', ''),
        'created_at': job.get('created_at', ''),
        'opens': opens_count,
        'clicks': clicks_count
    }), 200

@app.route('/api/batch/list', methods=['GET'])
@login_required
def list_batches():
    user = db.get_user_by_id(session['user_id'])
    if user['role'] == 'admin':
        batches = db.get_all_batch_jobs(limit=20)
    else:
        batches = db.get_all_batch_jobs_for_user(session['user_id'], limit=20)
    return jsonify(batches), 200

# ----------------------------------------------------------------------
# Bulk API (reuses batch)
# ----------------------------------------------------------------------
@app.route('/api/send/bulk', methods=['POST'])
@login_required
def send_bulk():
    data = request.json
    data['MessageStream'] = 'broadcast'
    return send_batch()

# ----------------------------------------------------------------------
# Webhook endpoint (public)
# ----------------------------------------------------------------------
@app.route('/api/webhook/postmark', methods=['POST'])
def postmark_webhook():
    data = request.json
    print(f"📨 Webhook received: {json.dumps(data, indent=2)}")
    
    record_type = data.get('RecordType')
    
    if record_type == 'Open':
        message_id = data.get('MessageID')
        recipient = data.get('Recipient')
        opened_at = data.get('OpenedAt') or datetime.now(timezone.utc).isoformat()
        user_agent = data.get('UserAgent')
        platform = data.get('Platform')
        os_family = data.get('OSFamily')
        client_name = data.get('ClientName')
        client_type = data.get('ClientType')
        db.log_open(message_id, recipient, opened_at, user_agent, platform, os_family, client_name, client_type)
        print(f"✅ Open logged for {recipient} (msg: {message_id})")
    
    elif record_type == 'Click':
        message_id = data.get('MessageID')
        recipient = data.get('Recipient')
        link = data.get('OriginalLink') or data.get('Link')
        clicked_at = data.get('ClickedAt') or datetime.now(timezone.utc).isoformat()
        user_agent = data.get('UserAgent')
        platform = data.get('Platform')
        os_family = data.get('OSFamily')
        client_name = data.get('ClientName')
        client_type = data.get('ClientType')
        db.log_click(message_id, recipient, link, clicked_at, user_agent, platform, os_family, client_name, client_type)
        print(f"✅ Click logged for {recipient} -> {link}")
    
    elif record_type == 'Bounce':
        message_id = data.get('MessageID')
        recipient = data.get('Recipient')
        bounce_type = data.get('Type')
        bounce_class = data.get('Class')
        description = data.get('Description')
        details = data.get('Details')
        bounced_at = data.get('BouncedAt') or datetime.now(timezone.utc).isoformat()
        can_retry = data.get('CanRetry', False)
        db.log_bounce(message_id, recipient, bounce_type, bounce_class, description, details, bounced_at, can_retry)
        print(f"⚠️ Bounce logged for {recipient}")
    
    elif record_type == 'SpamComplaint':
        message_id = data.get('MessageID')
        recipient = data.get('Recipient')
        complained_at = data.get('ComplainedAt') or datetime.now(timezone.utc).isoformat()
        user_agent = data.get('UserAgent')
        description = data.get('Description')
        db.log_spam_complaint(message_id, recipient, complained_at, user_agent, description)
        print(f"🚫 Spam complaint for {recipient}")
    
    return jsonify({'status': 'ok'}), 200

# ----------------------------------------------------------------------
# Clear logs (admin only)
# ----------------------------------------------------------------------
@app.route('/api/logs/clear', methods=['POST'])
@admin_required
def clear_logs():
    conn = db.get_db()
    try:
        conn.execute('DELETE FROM send_logs')
        conn.execute('DELETE FROM sent_emails')
        conn.commit()
        return jsonify({'success': True, 'message': 'All logs cleared'}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        conn.close()

# ----------------------------------------------------------------------
# debug logs (admin only)
# ----------------------------------------------------------------------
@app.route('/api/debug/message/<message_id>', methods=['GET'])
@admin_required
def debug_message(message_id):
    conn = db.get_db()
    row = conn.execute('SELECT * FROM send_logs WHERE message_id = ?', (message_id,)).fetchone()
    conn.close()
    if row:
        return jsonify(dict(row))
    else:
        return jsonify({'error': 'Message not found in send_logs'}), 404

# ----------------------------------------------------------------------
# Download failed emails (admin only)
# ----------------------------------------------------------------------
@app.route('/api/logs/failed/download', methods=['GET'])
@admin_required
def download_failed_emails():
    conn = db.get_db()
    rows = conn.execute('''
        SELECT DISTINCT recipient, error, created_at
        FROM send_logs
        WHERE status = 'failed'
        ORDER BY created_at DESC
    ''').fetchall()
    conn.close()

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Email', 'Error Message', 'Failed At'])
    for row in rows:
        writer.writerow([row['recipient'], row['error'], row['created_at']])

    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=failed_emails.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response

# ----------------------------------------------------------------------
# Download bounces and complaints (admin only)
# ----------------------------------------------------------------------
@app.route('/api/logs/bounces/download', methods=['GET'])
@admin_required
def download_bounces_complaints():
    bounces, complaints = db.get_bounces_and_complaints(limit=10000)
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Type', 'Email', 'Date', 'Reason/Description', 'MessageID'])
    for b in bounces:
        writer.writerow(['Bounce', b['recipient'], b['bounced_at'], f"{b['bounce_type']} - {b['description']}", b['message_id']])
    for c in complaints:
        writer.writerow(['SpamComplaint', c['recipient'], c['complained_at'], c.get('description', ''), c['message_id']])
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=bounces_and_complaints.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response

# ----------------------------------------------------------------------
# Postmark events (aggregated) - admin only
# ----------------------------------------------------------------------
@app.route('/api/logs/events', methods=['GET'])
@admin_required
def get_events():
    bounces, complaints = db.get_bounces_and_complaints(limit=500)
    return jsonify({'bounces': bounces, 'complaints': complaints}), 200

# ----------------------------------------------------------------------
# Postmark Statistics (global) - admin only
# ----------------------------------------------------------------------
@app.route('/api/postmark/stats', methods=['GET'])
@admin_required
def postmark_stats():
    headers = {
        'Accept': 'application/json',
        'X-Postmark-Server-Token': GLOBAL_POSTMARK_TOKEN
    }
    try:
        resp = requests.get(f'{POSTMARK_API_URL}/stats/outbound', headers=headers, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            return jsonify({
                'success': True,
                'sent': data.get('Sent', 0),
                'bounces': data.get('Bounces', 0),
                'spam_complaints': data.get('SpamComplaints', 0),
                'opens': data.get('UniqueOpens', 0),
                'clicks': data.get('UniqueClicks', 0)
            }), 200
        else:
            return jsonify({'success': False, 'error': 'Failed to fetch stats'}), resp.status_code
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ----------------------------------------------------------------------
# Get opens/clicks for a specific batch (ownership enforced)
# ----------------------------------------------------------------------
@app.route('/api/batch/<batch_id>/opens', methods=['GET'])
@login_required
def batch_opens(batch_id):
    job, err_resp, status = check_batch_ownership(batch_id)
    if err_resp:
        return err_resp, status
    opens = db.get_opens_for_batch(batch_id)
    return jsonify(opens), 200

@app.route('/api/batch/<batch_id>/clicks', methods=['GET'])
@login_required
def batch_clicks(batch_id):
    job, err_resp, status = check_batch_ownership(batch_id)
    if err_resp:
        return err_resp, status
    clicks = db.get_clicks_for_batch(batch_id)
    return jsonify(clicks), 200

# ----------------------------------------------------------------------
# Spam Check Proxy (public)
# ----------------------------------------------------------------------
@app.route('/api/spamcheck', methods=['POST'])
def spamcheck():
    data = request.json
    html_content = data.get('html', '')
    if not html_content:
        return jsonify({'error': 'No HTML content'}), 400

    email_raw = f"""From: sender@example.com
To: recipient@example.com
Subject: Spam Check Test
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

{html_content}
"""
    try:
        resp = requests.post(
            'https://spamcheck.postmarkapp.com/filter',
            headers={'Content-Type': 'application/json'},
            json={'email': email_raw, 'options': 'long'},
            timeout=30
        )
        if resp.headers.get('content-type', '').startswith('application/json'):
            result = resp.json()
            return jsonify(result), resp.status_code
        else:
            return jsonify({'success': False, 'error': f'SpamCheck API returned {resp.status_code}: {resp.text[:200]}'}), resp.status_code
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ----------------------------------------------------------------------
# Delete a single batch (ownership enforced)
# ----------------------------------------------------------------------
@app.route('/api/batch/<batch_id>', methods=['DELETE'])
@login_required
def delete_batch(batch_id):
    job, err_resp, status = check_batch_ownership(batch_id)
    if err_resp:
        return err_resp, status
    conn = db.get_db()
    try:
        conn.execute('DELETE FROM batch_jobs WHERE batch_id = ?', (batch_id,))
        conn.execute('DELETE FROM send_logs WHERE batch_id = ?', (batch_id,))
        conn.commit()
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        conn.close()

# ----------------------------------------------------------------------
# Delete multiple batches (ownership enforced per batch)
# ----------------------------------------------------------------------
@app.route('/api/batch/delete_bulk', methods=['POST'])
@login_required
def delete_batch_bulk():
    data = request.json
    batch_ids = data.get('batch_ids', [])
    if not batch_ids:
        return jsonify({'error': 'No batch IDs provided'}), 400
    
    user = db.get_user_by_id(session['user_id'])
    conn = db.get_db()
    try:
        for batch_id in batch_ids:
            job = db.get_batch_job(batch_id)
            if not job:
                continue
            if user['role'] != 'admin' and job.get('user_id') != session['user_id']:
                continue  # skip unauthorised
            conn.execute('DELETE FROM batch_jobs WHERE batch_id = ?', (batch_id,))
            conn.execute('DELETE FROM send_logs WHERE batch_id = ?', (batch_id,))
        conn.commit()
        return jsonify({'success': True, 'deleted': len(batch_ids)}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        conn.close()

# ----------------------------------------------------------------------
# Delete all batches (admin only)
# ----------------------------------------------------------------------
@app.route('/api/batch/delete_all', methods=['DELETE'])
@admin_required
def delete_all_batches():
    conn = db.get_db()
    try:
        conn.execute('DELETE FROM batch_jobs')
        conn.execute('DELETE FROM send_logs WHERE batch_id IS NOT NULL')
        conn.commit()
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        conn.close()

# ----------------------------------------------------------------------
# Stats and Logs endpoints (user-filtered)
# ----------------------------------------------------------------------
@app.route('/api/stats', methods=['GET'])
@login_required
def stats():
    user = db.get_user_by_id(session['user_id'])
    if user['role'] == 'admin':
        recent = db.get_recent_sent(50)
    else:
        recent = db.get_recent_sent_for_user(session['user_id'], 50)
    return jsonify({
        'recent': recent,
        'total_sent': len([e for e in recent if e['status'] == 'sent']),
        'total_failed': len([e for e in recent if e['status'] == 'failed'])
    })

@app.route('/api/logs', methods=['GET'])
@login_required
def get_logs():
    limit = request.args.get('limit', 500, type=int)
    user = db.get_user_by_id(session['user_id'])
    if user['role'] == 'admin':
        logs = db.get_send_logs(limit)
    else:
        logs = db.get_send_logs_for_user(session['user_id'], limit)
    return jsonify(logs)

@app.route('/api/bulk/status/<bulk_id>', methods=['GET'])
@login_required
def bulk_status(bulk_id):
    user = db.get_user_by_id(session['user_id'])
    if not user.get('postmark_token'):
        return jsonify({'error': 'No Postmark token assigned'}), 403
    headers = {
        'Accept': 'application/json',
        'X-Postmark-Server-Token': user['postmark_token']
    }
    try:
        resp = requests.get(f'{POSTMARK_API_URL}/email/bulk/{bulk_id}', headers=headers, timeout=30)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ----------------------------------------------------------------------
# Serve frontend with auth redirect for HTML pages
# ----------------------------------------------------------------------
@app.before_request
def check_authentication():
    public_paths = ['/login.html', '/api/auth/', '/api/webhook/postmark', '/api/spamcheck', '/css/', '/js/']
    if any(request.path.startswith(p) for p in public_paths):
        return None
    if request.path.startswith('/css/') or request.path.startswith('/js/'):
        return None
    if request.path.endswith('.html') and request.path != '/login.html':
        if 'user_id' not in session:
            return redirect('/login.html')
    if request.path.startswith('/api/') and not request.path.startswith('/api/auth/') and not request.path.startswith('/api/webhook/') and not request.path.startswith('/api/spamcheck'):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
    return None

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect('/login.html')
    return send_from_directory('frontend', 'index.html')

@app.route('/login.html')
def login_page():
    return send_from_directory('frontend', 'login.html')

@app.route('/<path:path>')
def static_files(path):
    if path == 'login.html':
        return redirect('/login.html')
    return send_from_directory('frontend', path)

if __name__ == '__main__':
    print("🚀 Server running at http://localhost:5000")
    app.run(debug=True, port=5000)
