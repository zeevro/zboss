#!/usr/bin/python3

import argparse
import json
import socket
import sys


SOCKET_PATH = '/tmp/zboss-{}.sock'


def server_command(device, command, wait=True):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(SOCKET_PATH.format(device))
        s.send(json.dumps({'command': command, 'wait': wait}).encode() + b'\n')
        return s.makefile('r').readline()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('-d', '--device', required=True)
    p.add_argument('-W', '--no-wait', action='store_true')
    p.add_argument('command', nargs=argparse.REMAINDER)
    args = p.parse_args()

    command = ' '.join(args.command)
    resp = json.loads(server_command(args.device, command, not args.no_wait))

    if args.no_wait:
        print('PID:', resp['pid'])
        return

    sys.stdout.write(resp['out'])
    sys.stderr.write(resp['err'])
    return resp['ret_code']


if __name__ == "__main__":
    sys.exit(main())
