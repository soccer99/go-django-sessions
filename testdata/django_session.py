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

settings.configure(
    SECRET_KEY=sys.argv[1],
    INSTALLED_APPS=["django.contrib.auth", "django.contrib.contenttypes", "django.contrib.sessions"],
    DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
    USE_TZ=True,
)
django.setup()

from django.contrib.sessions.backends.db import SessionStore  # noqa: E402

cmd = sys.argv[2]
if cmd == "version":
    print(django.get_version())
elif cmd == "auth_cases":
    from datetime import timedelta
    from types import SimpleNamespace
    from django.contrib.auth import get_user
    from django.contrib.auth.models import User
    from django.contrib.sessions.models import Session
    from django.core.management import call_command
    from django.test import override_settings
    from django.utils import timezone

    call_command("migrate", verbosity=0)
    cases = []
    backend = "django.contrib.auth.backends.ModelBackend"
    for name in ["valid", "expired", "password changed", "inactive", "deleted user",
                 "removed backend", "missing hash", "bad hash", "missing user id", "logged out"]:
        User.objects.all().delete()
        user = User.objects.create(username="example", password="encoded-password", is_active=True)
        store = SessionStore()
        store["_auth_user_id"] = str(user.pk)
        store["_auth_user_backend"] = backend
        store["_auth_user_hash"] = user.get_session_auth_hash()
        if name == "missing hash":
            del store["_auth_user_hash"]
        if name == "bad hash":
            store["_auth_user_hash"] = "bad"
        if name == "missing user id":
            del store["_auth_user_id"]
        store.save()
        key = store.session_key
        row = Session.objects.get(session_key=key)
        if name == "expired":
            row.expire_date = timezone.now() - timedelta(seconds=1)
            row.save()
        if name == "password changed":
            user.password = "changed-password"
            user.save()
        if name == "inactive":
            user.is_active = False
            user.save()
        if name == "deleted user":
            user.delete()
        if name == "logged out":
            store.flush()
        backends = [] if name == "removed backend" else [backend]
        with override_settings(AUTHENTICATION_BACKENDS=backends):
            authenticated = get_user(SimpleNamespace(session=SessionStore(session_key=key))).is_authenticated
        cases.append({
            "name": name, "key": key, "data": row.session_data,
            "expires": row.expire_date.isoformat(), "user_id": str(row.get_decoded().get("_auth_user_id", "")),
            "password": user.password, "active": user.is_active,
            "user_exists": name != "deleted user", "session_exists": name != "logged out",
            "backends": backends, "authenticated": authenticated,
        })
    print(json.dumps(cases))
elif cmd == "auth_hash":
    from django.contrib.auth.models import User
    print(User(password=sys.argv[3]).get_session_auth_hash())
elif cmd == "encode":
    print(SessionStore().encode(json.loads(sys.argv[3])))
elif cmd == "decode":
    print(json.dumps(SessionStore().decode(sys.argv[3])))
elif cmd == "authenticate":
    from django.core.management import call_command
    from django.contrib.auth import get_user, get_user_model
    from django.contrib.sessions.models import Session
    from django.contrib.sessions.middleware import SessionMiddleware
    from django.test import RequestFactory
    from django.utils import timezone
    from datetime import timedelta

    call_command("migrate", verbosity=0)
    user = get_user_model().objects.create(username="go-user", password=sys.argv[5])
    Session.objects.create(session_key=sys.argv[3], session_data=sys.argv[4],
                           expire_date=timezone.now() + timedelta(hours=1))
    request = RequestFactory().get("/", HTTP_COOKIE="sessionid=" + sys.argv[3])
    SessionMiddleware(lambda r: None).process_request(request)
    authenticated = get_user(request)
    initial_id = str(authenticated.pk) if authenticated.is_authenticated else None
    expected_hash = user.get_session_auth_hash()
    user.set_password("changed-password")
    user.save()
    after_change = get_user(request).is_authenticated
    print(json.dumps({"id": initial_id, "hash": expected_hash, "after_password_change": after_change}))
else:
    sys.exit("unknown command: " + cmd)
