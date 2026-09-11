"""Helper for the Go tests. It encodes or decodes session data with a real Django.

Usage:
    python django_session.py SECRET_KEY version
    python django_session.py SECRET_KEY encode '{"key": "value"}'
    python django_session.py SECRET_KEY decode SESSION_DATA
"""
import json
import sys

import django
from django.conf import settings

settings.configure(SECRET_KEY=sys.argv[1])
django.setup()

from django.contrib.sessions.backends.db import SessionStore  # noqa: E402

cmd = sys.argv[2]
if cmd == "version":
    print(django.get_version())
elif cmd == "encode":
    print(SessionStore().encode(json.loads(sys.argv[3])))
elif cmd == "decode":
    print(json.dumps(SessionStore().decode(sys.argv[3])))
else:
    sys.exit("unknown command: " + cmd)
