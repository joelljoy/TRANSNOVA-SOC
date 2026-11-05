"""Bounded in-memory session store for the synthetic login.

The cookie carries a random secret token. A separate opaque session_id (UUID) is the
value used in telemetry, so the cookie value never needs to be logged.
"""

from __future__ import annotations

import secrets
import threading
import uuid
from collections import OrderedDict
from dataclasses import dataclass

COOKIE_NAME = "hf_session"


@dataclass(frozen=True)
class Session:
    session_id: str
    user_id: int
    username: str


class SessionStore:
    def __init__(self, max_sessions: int) -> None:
        self._max = max_sessions
        self._data: OrderedDict[str, Session] = OrderedDict()
        self._lock = threading.Lock()

    def create(self, user_id: int, username: str) -> tuple[str, Session]:
        token = secrets.token_urlsafe(32)
        sess = Session(session_id=str(uuid.uuid4()), user_id=user_id, username=username)
        with self._lock:
            self._data[token] = sess
            while len(self._data) > self._max:  # evict oldest; bounded memory
                self._data.popitem(last=False)
        return token, sess

    def get(self, token: str | None) -> Session | None:
        if not token or len(token) > 128:
            return None
        with self._lock:
            return self._data.get(token)

    def delete(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._data.pop(token, None)

    def __len__(self) -> int:
        return len(self._data)
