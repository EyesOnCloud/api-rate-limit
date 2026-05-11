from flask import Flask, request, jsonify
import sqlite3
import os
import jwt
import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['SECRET_KEY'] = 'portal-secret-2024'

DB_PATH = '/app/data/portal.db'

# Rate limiter — keyed by client IP address
# Default limit applies to all routes unless overridden by decorator
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per minute"],
    storage_uri="memory://"
)


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def verify_token(request):
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None
    token = auth_header.split(' ')[1]
    try:
        decoded = jwt.decode(
            token,
            app.config['SECRET_KEY'],
            algorithms=['HS256']
        )
        return decoded
    except Exception:
        return None


# ── HEALTH CHECK ──────────────────────────────────────────────
@app.route('/health', methods=['GET'])
@limiter.exempt   # health check is exempt — monitoring tools need unrestricted access
def health():
    return jsonify({"status": "running", "message": "HR Portal API"})


# ── LOGIN ──────────────────────────────────────────────────────
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")   # RATE LIMIT: max 5 login attempts per IP per minute
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    username = data.get('username', '')
    password = data.get('password', '')
    ip = request.remote_addr

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password)
    )
    user = cursor.fetchone()

    cursor.execute(
        "INSERT INTO login_log (username, ip_address, success) VALUES (?,?,?)",
        (username, ip, 1 if user else 0)
    )
    conn.commit()
    conn.close()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    token = jwt.encode(
        {
            'user_id':  user['id'],
            'username': user['username'],
            'role':     user['role'],
            'exp':      datetime.datetime.utcnow() + datetime.timedelta(hours=2)
        },
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )
    return jsonify({"token": token, "role": user['role'], "message": "Login successful"})


# ── EMPLOYEES ─────────────────────────────────────────────────
@app.route('/employees', methods=['GET'])
@limiter.limit("30 per minute")
def get_employees():
    decoded = verify_token(request)
    if not decoded:
        return jsonify({"error": "Valid token required"}), 401

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users")
    users = cursor.fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])


# ── LOGIN AUDIT LOG ───────────────────────────────────────────
@app.route('/admin/login-log', methods=['GET'])
@limiter.limit("10 per minute")
def get_login_log():
    decoded = verify_token(request)
    if not decoded:
        return jsonify({"error": "Valid token required"}), 401
    if decoded.get('role') != 'admin':
        return jsonify({"error": "Admin role required"}), 403

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM login_log ORDER BY timestamp DESC LIMIT 100"
    )
    logs = cursor.fetchall()
    conn.close()
    return jsonify([dict(l) for l in logs])


# ── STATS ─────────────────────────────────────────────────────
@app.route('/admin/stats', methods=['GET'])
@limiter.limit("10 per minute")
def get_stats():
    decoded = verify_token(request)
    if not decoded:
        return jsonify({"error": "Valid token required"}), 401
    if decoded.get('role') != 'admin':
        return jsonify({"error": "Admin role required"}), 403

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM login_log")
    total = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) as failed FROM login_log WHERE success=0")
    failed = cursor.fetchone()['failed']

    cursor.execute("SELECT COUNT(*) as success FROM login_log WHERE success=1")
    success = cursor.fetchone()['success']

    cursor.execute("""
        SELECT ip_address, COUNT(*) as attempts
        FROM login_log
        WHERE success=0
        GROUP BY ip_address
        ORDER BY attempts DESC
        LIMIT 5
    """)
    top_offenders = cursor.fetchall()

    conn.close()

    return jsonify({
        "total_attempts": total,
        "successful":     success,
        "failed":         failed,
        "top_failing_ips": [dict(r) for r in top_offenders]
    })


# ── RATE LIMIT ERROR HANDLER ──────────────────────────────────
# Custom response when rate limit is exceeded — returns proper JSON
# instead of Flask-Limiter's default HTML error page
@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({
        "error": "Too many requests",
        "message": "Rate limit exceeded. Slow down.",
        "retry_after": str(e.description)
    }), 429


# ── START ─────────────────────────────────────────────────────
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
