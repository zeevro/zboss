#!/usr/bin/python3

import argparse
import json
import os
import subprocess
import time
import traceback
from urllib.request import urlopen, Request


class Client:
    def __init__(self, url_base, device_name):
        self.url_base = url_base
        self.device_name = device_name

    def server_request(self, endpoint: str, data: bytes = None):
        req = Request(f"{self.url_base.rstrip('/')}/{endpoint.lstrip('/')}", headers={'X-Device-Id': self.device_name, 'Content-Type': 'application/octet-stream'}, data=data)
        return json.load(urlopen(req))

    def register(self):
        privkey_path = os.path.expanduser('~/.ssh/id_rsa')
        pubkey_path = f'{privkey_path}.pub'
        if not os.path.exists(pubkey_path):
            subprocess.call(['ssh-keygen', '-b', '2048', '-t', 'rsa', '-f', privkey_path, '-q', '-N', ''])
        with open(pubkey_path, 'rb') as f:
            print(self.server_request('register', f.read().strip()))

    def get_ssh_command(self):
        server_params = self.server_request('onboard')
        ssh_command = ['ssh']
        if 'port' in server_params:
            ssh_command += ['-p', str(server_params['port'])]
        if 'user' in server_params:
            ssh_command += ['-l', server_params['user']]
        for k, v in server_params.get('options', {}).items():
            ssh_command += ['-o', f'{k}={v}']
        for dst, src in server_params.get('forwarded-ports', []):
            ssh_command += ['-R', f'{src}:127.0.0.1:{dst}']
        ssh_command.append(server_params['host'])
        ssh_command += server_params['command']
        return ssh_command

    def run_ssh(self, command):
        print(f'{command!r}')
        with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as ssh_proc:
            while 1:
                ret_code = ssh_proc.poll()
                if ret_code is not None:
                    break

                line = ssh_proc.stdout.readline().decode().strip()
                if not line:
                    continue

                print(f'line = {line!r}')

                try:
                    cmd_params = json.loads(line)

                    if cmd_params.get('wait', False):
                        with subprocess.Popen(cmd_params['command'], shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as cmd_proc:
                            ret_code = cmd_proc.wait()
                            resp = {'ret_code': ret_code, 'out': cmd_proc.stdout.read().decode(), 'err': cmd_proc.stderr.read().decode()}
                    else:
                        pid = subprocess.Popen(cmd_params['command'], shell=True).pid
                        resp = {'pid': pid}

                    ssh_proc.stdin.write(json.dumps(resp).encode())
                    ssh_proc.stdin.write(b'\n')
                    ssh_proc.stdin.flush()
                except Exception:
                    traceback.print_exc()

            print(f'ssh has died: {ssh_proc.stderr.read().decode().strip()}')

    def run(self):
        self.run_ssh(self.get_ssh_command())


def main():
    p = argparse.ArgumentParser()
    p.add_argument('-n', '--device-name')
    p.add_argument('-u', '--url-base')
    p.add_argument('-N', '--no-reconnect', action='store_true')
    args = p.parse_args()

    cli = Client(f"{args.url_base.rstrip('/')}/api/device", args.device_name)
    while 1:
        try:
            cli.register()
            cli.run()
        except Exception:
            traceback.print_exc()
        if args.no_reconnect:
            break
        time.sleep(5)


if __name__ == "__main__":
    main()

