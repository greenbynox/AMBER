import json
import sys
import traceback
import uuid
import urllib.request
from datetime import datetime, timezone

_config = {
    "endpoint": None,
    "project_id": None,
    "api_key": None,
    "environment": None,
    "release": None,
    "auto_capture": True,
    "max_breadcrumbs": 50,
}

_breadcrumbs = []
_prev_excepthook = None


def init(**options):
    _config.update(options)
    _install_excepthook()


def capture_exception(error, context=None):
    if context is None:
        context = {}

    if not _config.get("endpoint") or not _config.get("project_id") or not _config.get("api_key"):
        return

    stack = _format_stack(error)

    event = {
        "event_id": str(uuid.uuid4()),
        "project_id": _config["project_id"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": "error",
        "message": str(error),
        "exception": {
            "type": error.__class__.__name__ if error else "Exception",
            "message": str(error) if error else "Exception",
            "stacktrace": stack,
        },
        "context": {
            "env": _config.get("environment") or context.get("env"),
            "release": _config.get("release") or context.get("release"),
            "user": context.get("user"),
            "tags": context.get("tags"),
            "breadcrumbs": _merge_breadcrumbs(context.get("breadcrumbs")),
        },
        "sdk": {
            "name": "ember-python",
            "version": "0.1.0",
        },
    }

    _send_event(event)


def _format_stack(error):
    if not error:
        return None
    frames = []
    tb = error.__traceback__
    for frame in traceback.extract_tb(tb):
        frames.append(
            {
                "function": frame.name,
                "filename": frame.filename,
                "line": frame.lineno,
                "col": None,
                "in_app": True,
            }
        )
    return frames or None


def _send_event(event):
    data = json.dumps(event).encode("utf-8")
    url = _config["endpoint"].rstrip("/") + "/ingest"
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "x-ember-key": _config["api_key"],
        },
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass


def add_breadcrumb(message, category=None, data=None, level="info"):
    if not message:
        return
    _breadcrumbs.append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message": str(message),
            "category": category,
            "level": level,
            "data": data,
        }
    )
    if len(_breadcrumbs) > _config.get("max_breadcrumbs", 50):
        _breadcrumbs[:] = _breadcrumbs[-_config["max_breadcrumbs"] :]


def clear_breadcrumbs():
    _breadcrumbs.clear()


def _merge_breadcrumbs(extra):
    items = list(_breadcrumbs)
    if isinstance(extra, list):
        items.extend(extra)
    return items or None


def _install_excepthook():
    global _prev_excepthook
    if not _config.get("auto_capture"):
        return
    if _prev_excepthook is not None:
        return

    _prev_excepthook = sys.excepthook

    def _hook(exc_type, exc, tb):
        try:
            capture_exception(exc)
        finally:
            if _prev_excepthook:
                _prev_excepthook(exc_type, exc, tb)

    sys.excepthook = _hook
