import os
import uuid
import json
import socket
import ipaddress
import requests
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, redirect, render_template, Response, flash, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, func, desc
from sqlalchemy.orm import relationship, sessionmaker, scoped_session, declarative_base, joinedload
import geoip2.database
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)


def authenticate():
    return Response(
        'Login Required', 401,
        {'WWW-Authenticate': 'Basic realm="Tracking Dashboard"'}
    )


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_password_hash(DASH_PASS_HASH, auth.password):
            return authenticate()
        return f(*args, **kwargs)

    return decorated


limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["500/day", "100/hour"]
)

engine = create_engine('sqlite:///tracker.db')
Base = declarative_base()
Session = scoped_session(sessionmaker(bind=engine))


class Link(Base):
    __tablename__ = 'links'
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(100))
    created_at = Column(DateTime, default=datetime.now)
    visits = relationship('Visit', back_populates='link')


class User(Base):
    __tablename__ = 'users'
    id = Column(String(36), primary_key=True)
    visit_count = Column(Integer, default=0)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    visits = relationship('Visit', back_populates='user')


class Visit(Base):
    __tablename__ = 'visits'
    id = Column(Integer, primary_key=True)
    user_id = Column(String(36), ForeignKey('users.id'))
    link_id = Column(String(36), ForeignKey('links.id'))
    timestamp = Column(DateTime)
    ip_address = Column(String(45))
    city = Column(String(50))
    country = Column(String(50))
    lat = Column(String(15))
    lon = Column(String(15))
    user_agent = Column(String(200))
    referrer = Column(String(200))
    url_params = Column(String(500))
    user = relationship('User', back_populates='visits')
    link = relationship('Link', back_populates='visits')


Base.metadata.create_all(engine)

geo_reader = geoip2.database.Reader(os.getenv('GEOIP_PATH', 'GeoLite2-City.mmdb'))
DASH_PASS_HASH = generate_password_hash(os.getenv('DASH_PASS', 'default-password'))


@app.route('/track/<link_id>')
@limiter.limit("20/minute")
def track(link_id):
    session = Session()
    try:
        link = session.query(Link).get(link_id)
        if not link:
            return "Invalid tracking link", 404

        user_id = get_or_create_user()
        real_ip = get_real_ip()
        geo = get_geo_info(real_ip)

        user = session.query(User).get(user_id) or User(id=user_id)
        user.visit_count += 1
        user.last_seen = datetime.now()

        session.add(Visit(
            user_id=user_id,
            link_id=link_id,
            timestamp=datetime.now(),
            ip_address=real_ip,
            city=geo['city'],
            country=geo['country'],
            lat=str(geo['lat']) if geo['lat'] else None,
            lon=str(geo['lon']) if geo['lon'] else None,
            user_agent=request.user_agent.string,
            referrer=request.referrer,
            url_params=json.dumps(dict(request.args))
        ))
        session.commit()

        resp = redirect("https://www.google.com")
        resp.set_cookie('user_id', user_id, max_age=31536000)
        return resp
    finally:
        Session.remove()


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return True


def get_real_ip():
    xff = [ip.strip() for ip in request.headers.get('X-Forwarded-For', '').split(',')]
    for ip in xff:
        if ip and not is_private_ip(ip): return ip
    if not is_private_ip(ip := request.remote_addr): return ip
    try:
        return requests.get('https://api.ipify.org', timeout=2).text
    except:
        return ip


def get_geo_info(ip):
    try:
        if is_private_ip(ip):
            ext_ip = requests.get('https://api.ipify.org', timeout=2).text
            resp = geo_reader.city(ext_ip)
        else:
            resp = geo_reader.city(ip)
        return {
            'city': resp.city.name or 'Unknown',
            'country': resp.country.name or 'Unknown',
            'lat': resp.location.latitude,
            'lon': resp.location.longitude
        }
    except Exception as e:
        print(f"GeoIP Error: {str(e)}")
        return {'city': 'Unknown', 'country': 'Unknown', 'lat': None, 'lon': None}


def get_or_create_user():
    session = Session()
    try:
        if not (user_id := request.cookies.get('user_id')):
            user_id = str(uuid.uuid4())
            session.add(User(id=user_id, first_seen=datetime.now(), last_seen=datetime.now()))
            session.commit()
        elif not session.query(User).get(user_id):
            session.add(User(id=user_id, first_seen=datetime.now(), last_seen=datetime.now()))
            session.commit()
        return user_id
    finally:
        Session.remove()


@app.route('/link/<link_id>', methods=['DELETE'])
@requires_auth
def delete_link(link_id):
    session = Session()
    try:
        link = session.query(Link).get(link_id)
        if not link: return "Link not found", 404

        session.delete(link)
        session.commit()
        return '', 204
    finally:
        Session.remove()


@app.route('/dashboard', methods=['GET', 'POST'])
@requires_auth
def dashboard():
    session = Session()
    try:
        if request.method == 'POST':
            name = request.form.get('name').strip()
            if not name:
                flash('Link name is required', 'error')
            elif session.query(Link).filter(func.lower(Link.name) == func.lower(name)).first():
                flash('Link name already exists', 'error')
            else:
                new_link = Link(name=name)
                session.add(new_link)
                session.commit()
                flash('Link created successfully', 'success')
            return redirect(url_for('dashboard'))

        # Rest of the dashboard logic
        links = session.query(Link).options(joinedload(Link.visits)).all()
        links_with_stats = []
        for link in links:
            visit_count = session.query(func.count(Visit.id)).filter(Visit.link_id == link.id).scalar()
            links_with_stats.append({
                'link': link,
                'visit_count': visit_count,
                'last_activity': session.query(func.max(Visit.timestamp)).filter(Visit.link_id == link.id).scalar()
            })

        # Timeline data
        now = datetime.now()
        cutoff = now - timedelta(hours=24)
        timeline = session.query(
            func.strftime('%Y-%m-%d %H:00', Visit.timestamp).label('hour'),
            func.count().label('count')
        ).filter(Visit.timestamp >= cutoff).group_by('hour').all()

        hours = [(now - timedelta(hours=h)).strftime('%Y-%m-%d %H:00') for h in range(24)]
        hours.reverse()
        timeline_dict = {h[0]: h[1] for h in timeline}
        timeline_data = [timeline_dict.get(h, 0) for h in hours]

        # Map data
        map_data = session.query(Visit).filter(
            Visit.lat.isnot(None),
            Visit.lon.isnot(None)
        ).limit(100).all()

        # Top location
        top_location = session.query(
            Visit.country,
            func.count().label('count')
        ).filter(Visit.country != 'Unknown'
                 ).group_by(Visit.country).order_by(desc('count')).first() or ('Unknown', 0)

        return render_template('dashboard.html',
                               total_visits=session.query(Visit).count(),
                               unique_users=session.query(User).count(),
                               recent_visits=session.query(Visit).options(joinedload(Visit.link))
                               .order_by(desc(Visit.timestamp)).limit(20).all(),
                               map_data=map_data,
                               timeline_labels=hours,
                               timeline_data=timeline_data,
                               top_location=top_location,
                               local_ip=socket.gethostbyname(socket.gethostname()),
                               links=links_with_stats)  # Removed error=error parameter
    finally:
        Session.remove()


@app.route('/user/<user_id>')
def user_history(user_id):
    session = Session()
    try:
        user = session.query(User).get(user_id)
        if not user: return "User not found", 404
        visits = session.query(Visit).options(joinedload(Visit.link)).filter_by(user_id=user_id).order_by(
            desc(Visit.timestamp)).all()
        return render_template('user_history.html', user=user, visits=visits)
    finally:
        Session.remove()


@app.teardown_appcontext
def shutdown_session(exception=None): Session.remove()


if __name__ == '__main__':
    print(f"DASHBOARD URL: http://{socket.gethostbyname(socket.gethostname())}:5000/dashboard\n")
    app.run(host='0.0.0.0', port=5000, debug=os.getenv('DEBUG', False))
