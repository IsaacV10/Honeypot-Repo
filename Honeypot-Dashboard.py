"""
JM Technologies - Honeypot Dashboard Backend
Run with: python3 dashboard.py
Serves on: http://0.0.0.0:5000
"""

from flask import Flask, jsonify, send_from_directory
import json
import os
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone

app = Flask(__name__, static_folder='static')

AUTH_LOG = 'auth_attempts.json'
CMD_LOG  = 'commands.json'

# ---- GeoIP cache (avoids hammering the free API) ----
_geo_cache = {}
_geo_cache_file = 'geo_cache.json'

def load_geo_cache():
    global _geo_cache
    if os.path.exists(_geo_cache_file):
        try:
            with open(_geo_cache_file) as f:
                _geo_cache = json.load(f)
        except Exception:
            _geo_cache = {}

def save_geo_cache():
    try:
        with open(_geo_cache_file, 'w') as f:
            json.dump(_geo_cache, f)
    except Exception:
        pass

def lookup_geo(ip):
    """Look up GeoIP info for an IP address."""
    if not ip or ip in ('127.0.0.1', 'localhost', '::1'):
        return None
    if ip in _geo_cache:
        return _geo_cache[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,org"
        req = urllib.request.Request(url, headers={'User-Agent': 'HoneypotDashboard/1.0'})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            if data.get('status') == 'success':
                geo = {
                    'country':     data.get('country', 'Unknown'),
                    'countryCode': data.get('countryCode', ''),
                    'region':      data.get('regionName', ''),
                    'city':        data.get('city', ''),
                    'lat':         data.get('lat', 0),
                    'lon':         data.get('lon', 0),
                    'org':         data.get('org', ''),
                }
                _geo_cache[ip] = geo
                save_geo_cache()
                return geo
    except Exception:
        pass
    return None


def read_json_log(filepath):
    events = []
    try:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except FileNotFoundError:
        pass
    return events


@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/api/auth')
def api_auth():
    return jsonify(read_json_log(AUTH_LOG))


@app.route('/api/commands')
def api_commands():
    return jsonify(read_json_log(CMD_LOG))


@app.route('/api/geo')
def api_geo():
    """Return GeoIP data for all unique attacking IPs."""
    auth_events = read_json_log(AUTH_LOG)
    attempts = [e for e in auth_events if e.get('event') == 'auth_attempt']

    unique_ips = list(set(e.get('ip') for e in attempts if e.get('ip')))

    results = []
    for ip in unique_ips[:50]:
        geo = lookup_geo(ip)
        if geo:
            count = sum(1 for e in attempts if e.get('ip') == ip)
            results.append({
                'ip':          ip,
                'count':       count,
                'country':     geo['country'],
                'countryCode': geo['countryCode'],
                'city':        geo['city'],
                'region':      geo['region'],
                'lat':         geo['lat'],
                'lon':         geo['lon'],
                'org':         geo['org'],
            })
        time.sleep(0.05)

    results.sort(key=lambda x: x['count'], reverse=True)
    return jsonify(results)


@app.route('/api/stats')
def api_stats():
    auth_events = read_json_log(AUTH_LOG)
    cmd_events  = read_json_log(CMD_LOG)

    attempts    = [e for e in auth_events if e.get('event') == 'auth_attempt']
    connections = [e for e in auth_events if e.get('event') == 'connection']
    commands    = [e for e in cmd_events  if e.get('event') == 'command']

    ip_counts   = Counter(e.get('ip')       for e in attempts if e.get('ip'))
    user_counts = Counter(e.get('username') for e in attempts if e.get('username'))
    pass_counts = Counter(e.get('password') for e in attempts if e.get('password'))
    cmd_counts  = Counter(e.get('command')  for e in commands if e.get('command'))

    hourly = Counter()
    for e in attempts:
        ts = e.get('timestamp', '')
        if ts:
            try:
                hourly[ts[:13]] += 1
            except Exception:
                pass

    return jsonify({
        "total_attempts":    len(attempts),
        "total_connections": len(connections),
        "unique_ips":        len(ip_counts),
        "total_commands":    len(commands),
        "top_ips":           ip_counts.most_common(10),
        "top_usernames":     user_counts.most_common(10),
        "top_passwords":     pass_counts.most_common(10),
        "top_commands":      cmd_counts.most_common(10),
        "hourly_activity":   sorted(hourly.items())[-24:],
        "recent_attempts":   attempts[-50:][::-1],
    })


load_geo_cache()

if __name__ == '__main__':
    os.makedirs('static', exist_ok=True)
    print("Starting JM Technologies Honeypot Dashboard on http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
