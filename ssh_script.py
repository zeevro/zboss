#!/usr/bin/python3.8

import os

orig_ppid = os.getppid()

import atexit
import threading
import time
import select
import sys
from socketserver import UnixStreamServer, StreamRequestHandler


class MyUnixStreamServer(UnixStreamServer):
    def server_bind(self):
        super().server_bind()
        os.chmod(self.server_address, 0o0777)


class MyRequestHandler(StreamRequestHandler):
    def handle(self):
        l = [sys.stdin.buffer, self.rfile]
        d = {sys.stdin.buffer: self.wfile, self.rfile: sys.stdout.buffer}
        done = False
        while not done:
            rl, wl, xl = select.select(l, [], [], 0.2)
            for rf in rl:
                buf = rf.readline()
                if not buf:
                    done = True
                    break
                d[rf].write(buf)
                d[rf].flush()
        print('Done.')


def main():
    sock_path = sys.argv[1]

    atexit.register(os.remove, sock_path)

    server = MyUnixStreamServer(sock_path, MyRequestHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    while orig_ppid == os.getppid():
        time.sleep(.2)

    server.shutdown()


if __name__ == "__main__":
    main()
