import os, ipaddress, json, queue, threading, uuid, secrets, sys, tempfile, re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
import paramiko
from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for, stream_with_context
from werkzeug.security import check_password_hash, generate_password_hash

APP_NAME = 'ELSINY_5G'
APP_DIR = Path(__file__).resolve().parent
BASE_DIR = Path(os.environ.get('DATA_DIR', str(APP_DIR))).resolve()
BASE_DIR.mkdir(parents=True, exist_ok=True)
SETTINGS_FILE = BASE_DIR / 'ELSINY_5G_settings.json'
DEFAULTS = {"app_username":"admin", "app_password_hash":generate_password_hash("admin"), "ssh_username":"root", "ssh_password":"", "ssh_port":22, "workers":40}

def load_settings():
    data = DEFAULTS.copy()
    try:
        saved = json.loads(SETTINGS_FILE.read_text(encoding='utf-8'))
        for key in data:
            if key in saved: data[key] = saved[key]
    except (OSError, ValueError, TypeError):
        pass
    if not os.environ.get('ELSINY_5G_SECRET'):
        try: secret = json.loads(SETTINGS_FILE.read_text(encoding='utf-8')).get('secret_key')
        except Exception: secret = None
    else: secret = os.environ['ELSINY_5G_SECRET']
    return data, secret or secrets.token_hex(32)

settings, SECRET_KEY = load_settings()

def persist_settings():
    payload = settings.copy()
    payload['secret_key'] = app.secret_key
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='elsiny_', suffix='.tmp', dir=str(BASE_DIR))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        os.replace(tmp, SETTINGS_FILE)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

app = Flask(__name__)
app.secret_key = SECRET_KEY
scan_jobs = {}

def login_required(fn):
    @wraps(fn)
    def w(*a, **k):
        if not session.get('logged_in'):
            if request.path.startswith('/api/') or request.path.startswith('/scan/'): return jsonify({'error':'Unauthorized'}), 401
            return redirect(url_for('login'))
        return fn(*a, **k)
    return w

def parse_range(v):
    v = (v or '').strip()
    if not v: return []
    if '/' in v:
        net = ipaddress.ip_network(v, strict=False)
        if net.num_addresses > 65536: raise ValueError('Range too large (maximum 65,536 addresses)')
        return [str(x) for x in net.hosts()]
    if '-' in v:
        a, b = [x.strip() for x in v.split('-', 1)]
        aa, bb = ipaddress.ip_address(a), ipaddress.ip_address(b)
        if aa.version != 4 or bb.version != 4 or int(bb) < int(aa): raise ValueError('Invalid IP range')
        if int(bb) - int(aa) > 65535: raise ValueError('Range too large (maximum 65,536 addresses)')
        return [str(ipaddress.IPv4Address(i)) for i in range(int(aa), int(bb)+1)]
    return [str(ipaddress.ip_address(v))]

def collect_ips(a, b):
    out, seen = [], set()
    for r in (a, b):
        for ip in parse_range(r):
            if ip not in seen: seen.add(ip); out.append(ip)
    return out

def ssh_scan(ip, cfg):
    c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(ip, port=int(cfg['ssh_port']), username=cfg['ssh_username'], password=cfg['ssh_password'], timeout=3, banner_timeout=4, auth_timeout=4, look_for_keys=False, allow_agent=False)
        def cmd(x):
            _, out, _ = c.exec_command(x, timeout=6)
            return out.read().decode('utf-8', 'replace').strip()
        release = cmd('cat /etc/openwrt_release 2>/dev/null')
        if 'openwrt' not in release.lower() and 'openwrt' not in cmd('uname -a').lower(): return None
        hostname = cmd("uci -q get system.@system[0].hostname 2>/dev/null || hostname") or ip
        model = cmd("cat /tmp/sysinfo/model 2>/dev/null || cat /proc/device-tree/model 2>/dev/null | tr -d '\\000' || ubus call system board 2>/dev/null | jsonfilter -e '@.model' 2>/dev/null") or 'Unknown'
        # Prefer named DSA interfaces. ethtool is the first source; sysfs is the fallback.
        raw = cmd(r'''for p in lan1 lan2 lan3 lan4 wan; do
 [ -d "/sys/class/net/$p" ] || continue
 state=$(cat "/sys/class/net/$p/operstate" 2>/dev/null)
 carrier=$(cat "/sys/class/net/$p/carrier" 2>/dev/null)
 speed=""
 if command -v ethtool >/dev/null 2>&1; then speed=$(ethtool "$p" 2>/dev/null | sed -n 's/^[[:space:]]*Speed:[[:space:]]*//p' | head -n1); fi
 [ -n "$speed" ] || speed=$(cat "/sys/class/net/$p/speed" 2>/dev/null)
 echo "$p|$state|$carrier|$speed"
done''')
        interfaces = {}
        for line in raw.splitlines():
            parts = line.split('|', 3)
            if len(parts) != 4: continue
            name, state, carrier, speed = parts
            if carrier == '0' or state.lower() == 'down': status, shown = 'down', 'DOWN'
            else:
                match = re.search(r'(\d+)', speed)
                mbps = int(match.group(1)) if match else 0
                if mbps in (10, 100, 1000, 2500, 5000, 10000): shown = f'{mbps}M' if mbps < 1000 else f'{mbps//1000}G'
                elif state.lower() == 'up' or carrier == '1': shown = 'UP'
                else: shown = 'N/A'
                status = 'up' if shown != 'N/A' else state or 'N/A'
            interfaces[name] = {'state': status, 'speed': shown, 'interface': name}
        ports = {}
        for label, name in [('LAN1','lan1'),('LAN2','lan2'),('LAN3','lan3'),('LAN4','lan4'),('WAN','wan')]:
            ports[label] = interfaces.get(name, {'state':'N/A','speed':'N/A','interface':name})
        # Legacy swconfig devices can expose only ethX. Report those interfaces without pretending their physical mapping is universal.
        if not any(k in interfaces for k in ('lan1','lan2','lan3','lan4','wan')):
            legacy = [n for n in ('eth0','eth1','eth2','eth3','eth4') if n in interfaces]
            for idx, name in enumerate(legacy[:5]):
                label = f'LAN{idx+1}' if idx < 4 else 'WAN'
                ports[label] = interfaces[name]
        return {'ip':ip, 'hostname':hostname, 'model':model, 'ports':ports}
    except Exception:
        return None
    finally:
        try: c.close()
        except Exception: pass

def emit(j, e):
    if j in scan_jobs: scan_jobs[j]['events'].put(e)

def run_scan(j, ips, cfg):
    job = scan_jobs[j]; found = {}
    try:
        with ThreadPoolExecutor(max_workers=max(1, min(int(cfg['workers']), 100))) as ex:
            fs = {ex.submit(ssh_scan, ip, cfg):ip for ip in ips}
            for f in as_completed(fs):
                if job['stop'].is_set(): break
                ip = fs[f]; job['done'] += 1
                try: result = f.result()
                except Exception: result = None
                if result:
                    found[result['ip']] = result
                    ordered = sorted(found.values(), key=lambda x:(x['hostname'].lower(), x['ip']))
                    emit(j, {'type':'device','device':result,'devices':ordered,'done':job['done'],'total':len(ips)})
                else: emit(j, {'type':'progress','done':job['done'],'total':len(ips),'ip':ip})
        emit(j, {'type':'complete','devices':sorted(found.values(),key=lambda x:(x['hostname'].lower(),x['ip'])),'done':job['done'],'total':len(ips),'stopped':job['stop'].is_set()})
    finally: job['finished'] = True

@app.route('/')
def index(): return redirect(url_for('login')) if not session.get('logged_in') else render_template('index.html')

@app.route('/login', methods=['GET','POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form.get('username','') == settings['app_username'] and check_password_hash(settings['app_password_hash'], request.form.get('password','')):
            session['logged_in'] = True; return redirect(url_for('index'))
        error = 'Invalid username or password'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('login'))

@app.get('/api/settings')
@login_required
def get_settings():
    return jsonify({'ssh_username':settings['ssh_username'],'ssh_port':settings['ssh_port'],'workers':settings['workers'],'app_username':settings['app_username']})

@app.post('/api/settings')
@login_required
def save_settings():
    d = request.get_json(force=True) or {}
    try:
        if d.get('app_username'): settings['app_username'] = d['app_username'].strip()
        if d.get('app_password'): settings['app_password_hash'] = generate_password_hash(d['app_password'])
        if 'ssh_username' in d: settings['ssh_username'] = d['ssh_username'].strip()
        if 'ssh_password' in d and d['ssh_password'] != '': settings['ssh_password'] = d['ssh_password']
        if 'ssh_port' in d:
            port = int(d['ssh_port'])
            if not 1 <= port <= 65535: raise ValueError('SSH port must be between 1 and 65535')
            settings['ssh_port'] = port
        if 'workers' in d:
            workers = int(d['workers'])
            if not 1 <= workers <= 100: raise ValueError('Workers must be between 1 and 100')
            settings['workers'] = workers
        persist_settings()
        return jsonify({'ok':True,'message':'Settings saved beside the application'})
    except (ValueError, OSError) as e: return jsonify({'error':str(e)}), 400

@app.post('/api/scan')
@login_required
def start_scan():
    d = request.get_json(force=True) or {}
    try: ips = collect_ips(d.get('range1',''), d.get('range2',''))
    except Exception as e: return jsonify({'error':str(e)}), 400
    if not ips: return jsonify({'error':'Enter at least one IP range'}), 400
    cfg = {k:settings[k] for k in ('ssh_username','ssh_password','ssh_port','workers')}
    j = str(uuid.uuid4()); scan_jobs[j] = {'events':queue.Queue(),'stop':threading.Event(),'finished':False,'done':0}
    threading.Thread(target=run_scan,args=(j,ips,cfg),daemon=True).start()
    return jsonify({'job_id':j,'total':len(ips)})

@app.get('/scan/<j>')
@login_required
def stream(j):
    job = scan_jobs.get(j)
    if not job: return jsonify({'error':'Scan not found'}), 404
    @stream_with_context
    def gen():
        while True:
            if job['finished'] and job['events'].empty(): break
            try:
                event = job['events'].get(timeout=15); yield 'data: '+json.dumps(event)+'\n\n'
                if event.get('type') == 'complete': break
            except queue.Empty: yield ': keepalive\n\n'
    return Response(gen(), mimetype='text/event-stream')

@app.post('/api/scan/<j>/stop')
@login_required
def stop(j):
    if j not in scan_jobs: return jsonify({'error':'Scan not found'}), 404
    scan_jobs[j]['stop'].set(); return jsonify({'ok':True})

@app.get('/healthz')
def healthz():
    return jsonify({'ok': True, 'app': APP_NAME})

if __name__ == '__main__':
    try: persist_settings()
    except OSError: pass
    app.run(host=os.environ.get('HOST', '0.0.0.0'), port=int(os.environ.get('PORT', '7070')), debug=False, threaded=True)
