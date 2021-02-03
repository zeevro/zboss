import json
import os
import re
import socket
import subprocess
import time
import traceback

from flask import Flask, abort, render_template, request, redirect, url_for, jsonify
from flask_login import LoginManager, login_required, UserMixin, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.config.from_pyfile(os.path.join(os.path.dirname(__file__), 'settings.cfg'))
login_mgr = LoginManager(app)
login_mgr.login_view = 'login'


@login_mgr.user_loader
class User(UserMixin):
    @staticmethod
    def _load_users():
        with open(os.path.join(os.path.dirname(__file__), 'users.json')) as f:
            return json.load(f)

    def __init__(self, user_id):
        for user in self._load_users():
            if str(user['id']) == str(user_id):
                self.__dict__.update(user)
                break
        else:
            raise KeyError('No such user')

    @classmethod
    def get_by_username(cls, username):
        for user in cls._load_users():
            if user['username'].lower() == username.lower():
                return cls(user['id'])
        return None


with open(os.path.join(os.path.dirname(__file__), 'devices.json')) as f:
    DEVICES = [(d['name'], d['ports']) for d in json.load(f)]

DEVICES_DICT = dict(DEVICES)

with open(os.path.join(os.path.dirname(__file__), 'commands.json')) as f:
    COMMANDS = json.load(f)

SOCKET_PATH = '/tmp/zboss-{}.sock'


def get_client_ip_from_pid(pid):
    try:
        with open(f'/proc/{pid}/environ') as f:
            for env in f.read().split('\0'):
                if env.startswith('SSH_CLIENT'):
                    return env.split('=', 1)[1].split()[0]
    except Exception:
        traceback.print_exc()

    return 'unknonwn'


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    user = User.get_by_username(request.form['username'])
    if user is None or not check_password_hash(user.password, request.form['password']):
        return render_template('login.html', error_msg='Wrong user name or password')
    login_user(user)
    return redirect(request.form.get('next', url_for('index')))


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    netstat = subprocess.check_output(['netstat', '-nlpx'], stderr=subprocess.PIPE).decode()
    online_devices_pids = dict(map(reversed, re.findall(r'(\d+)/[\w\.\+\-]+\s+' + SOCKET_PATH.format(r'([\w\-]+)'), netstat)))
    devices = [
        {
            'name': name,
            'is_online': name in online_devices_pids,
            'ip': get_client_ip_from_pid(online_devices_pids[name]) if name in online_devices_pids else 'offline',
        }
        for name, ports in DEVICES
    ]

    return render_template('index.html', devices=devices, commands=COMMANDS, now=time.strftime('%Y-%m-%d %H:%M:%S'))


@app.route('/api/server/command')
@login_required
def server_command():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCKET_PATH.format(request.args['device']))
        s.send(json.dumps({'command': request.args['command'], 'wait': request.args.get('wait', False)}).encode() + b'\n')
        return s.makefile('r').readline()


@app.route('/api/device/register', methods=['POST'])
def device_register():
    device_pubkey = request.data
    authkeys_path = os.path.expanduser('~/.ssh/authorized_keys')
    should_add = True
    if os.path.exists(authkeys_path):
        with open(authkeys_path, 'rb') as f:
            for line in f:
                if line.strip() == device_pubkey:
                    should_add = False
                    break
    elif not os.path.exists(os.path.dirname(authkeys_path)):
        os.makedirs(os.path.dirname(authkeys_path), exist_ok=True)
    print(f'pubkey for {device_pubkey.split()[-1]} was{" not" if should_add else ""} found in {authkeys_path}')
    if should_add:
        with open(authkeys_path, 'ab') as f:
            f.write(device_pubkey + b'\n')
    resp = {'success': True}
    return jsonify(resp)


@app.route('/api/device/onboard')
def device_onboard():
    device_name = request.headers['X-Device-Id']
    if device_name not in DEVICES_DICT:
        return abort(404)

    forwarded_ports = DEVICES_DICT[device_name]
    sock_path = SOCKET_PATH.format(device_name)

    resp = {
        'forwarded-ports': forwarded_ports,
        'options': {
            'ServerAliveInterval': 30,
            'ExitOnForwardFailure': 'yes',
            'StrictHostKeyChecking': 'no',
        },
        'user': app.config['SSH_USER'],
        'host': app.config['SSH_HOST'],
        'port': app.config['SSH_PORT'],
        'command': [os.path.join(os.path.abspath(os.path.dirname(__file__)), 'ssh_script.py'), sock_path],
    }

    return jsonify(resp)
