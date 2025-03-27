import contextlib
import json
import os
import socket
import sqlite3
import uuid
from datetime import datetime

import geoip2.database
from flask import Flask, request, redirect, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

# Configuration
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Rate limiting configuration
app.config['RATELIMIT_STORAGE_URI'] = 'memory://'
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["500 per day", "100 per hour"]
)

# Database setup
DATABASE = 'tracker.db'


def init_db():
    with contextlib.closing(sqlite3.connect(DATABASE)) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                visit_count INTEGER DEFAULT 0,
                first_seen DATETIME,
                last_seen DATETIME
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS visits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                timestamp DATETIME,
                ip_address TEXT,
                city TEXT,
                country TEXT,
                user_agent TEXT,
                referrer TEXT,
                url_params TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        conn.commit()


init_db()

# GeoIP setup
geo_reader = geoip2.database.Reader('GeoLite2-City.mmdb')

# Dashboard credentials
DASH_PASS_HASH = generate_password_hash(os.getenv('DASH_PASS', 'default-password'))


def get_geo_info(ip):
    try:
        if ip in ['127.0.0.1', '::1']:
            return ('Localhost', 'Local Network')

        response = geo_reader.city(ip)
        city = response.city.name or 'Unknown City'
        country = response.country.name or 'Unknown Country'
        return (city, country)
    except Exception as e:
        print(f"GeoIP Error: {str(e)}")
        return ('Unknown', 'Unknown')


def get_or_create_user():
    user_id = request.cookies.get('user_id')
    if not user_id:
        user_id = str(uuid.uuid4())
        with sqlite3.connect(DATABASE) as conn:
            conn.execute('''
                INSERT INTO users (id, first_seen, last_seen)
                VALUES (?, ?, ?)
            ''', (user_id, datetime.now(), datetime.now()))
            conn.commit()
    return user_id


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip


@app.route('/track')
@limiter.limit("20/minute")
def track():
    user_id = get_or_create_user()
    ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    city, country = get_geo_info(ip)

    with sqlite3.connect(DATABASE) as conn:
        # Record visit
        conn.execute('''
            INSERT INTO visits 
            (user_id, timestamp, ip_address, city, country, user_agent, referrer, url_params)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            user_id,
            datetime.now().isoformat(),
            ip,
            city,
            country,
            str(request.user_agent),
            request.referrer,
            json.dumps(dict(request.args))
        ))

        # Update user stats
        conn.execute('''
            UPDATE users 
            SET visit_count = visit_count + 1,
                last_seen = ?
            WHERE id = ?
        ''', (datetime.now(), user_id))

        conn.commit()

        resp = redirect("https://www.google.com")
        resp.set_cookie('user_id', user_id, max_age=60 * 60 * 24 * 365)
    return resp


@app.route('/dashboard')
def dashboard():
    auth = request.authorization
    if not auth or not check_password_hash(DASH_PASS_HASH, auth.password):
        return ('Login required', 401,
                {'WWW-Authenticate': 'Basic realm="Login Required"'})

    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # General stats
        total_visits = cursor.execute('SELECT COUNT(*) FROM visits').fetchone()[0]
        unique_users = cursor.execute('SELECT COUNT(*) FROM users').fetchone()[0]

        # Recent visits with user info
        recent_visits = cursor.execute('''
            SELECT visits.*, users.visit_count, users.first_seen 
            FROM visits 
            JOIN users ON visits.user_id = users.id
            ORDER BY visits.timestamp DESC 
            LIMIT 20
        ''').fetchall()

        # Top locations
        top_locations = cursor.execute('''
            SELECT country, city, COUNT(*) as count 
            FROM visits 
            GROUP BY country, city 
            ORDER BY count DESC 
            LIMIT 10
        ''').fetchall()

    local_ip = get_local_ip()

    return render_template('dashboard.html',
                           total_visits=total_visits,
                           unique_users=unique_users,
                           recent_visits=recent_visits,
                           top_locations=top_locations,
                           local_ip=local_ip)


if __name__ == '__main__':
    host = '0.0.0.0'  # Accessible from other devices
    port = 5000
    print(f"\nAccess tracking links from other devices using:")
    print(f"http://{get_local_ip()}:{port}/track?your_params=here")
    print(f"Dashboard: http://{get_local_ip()}:{port}/dashboard\n")
    app.run(host=host, port=port, debug=True)
    # http://localhost:5000/track?campaign=test123