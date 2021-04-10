import argparse
from getpass import getpass
import json
import os
import sys

from werkzeug.security import generate_password_hash


USERS_PATH = os.path.join(os.path.dirname(__file__), 'users.json')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('-u', '--username')
    p.add_argument('-p', '--password')
    p.add_argument('-W', '--overwrite', action='store_true')
    args = p.parse_args()

    username = args.username or input('Enter username: ')
    password_hash = generate_password_hash(args.password or getpass('Enter password: '))

    if os.path.exists(USERS_PATH):
        with open(USERS_PATH) as f:
            users = json.load(f)
    else:
        users = []

    max_id = 0
    for user in users:
        if username.lower() == user['username'].lower():
            if not args.overwrite:
                print('Username already exists!', file=sys.stderr)
                return

            user['password'] = password_hash
            break
        max_id = max(max_id, user['id'])
    else:
        users.append({
            'id': max_id + 1,
            'username': username,
            'password': password_hash,
        })

    with open(USERS_PATH, 'w') as f:
        json.dump(users, f, indent=4, separators=(',', ': '))


if __name__ == "__main__":
    main()
