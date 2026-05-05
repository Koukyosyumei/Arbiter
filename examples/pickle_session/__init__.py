"""pickle_session — toy session-blob loader with an unsafe-deserialization ACE bug.

Public entry point: :func:`load_session`. Intended use case is loading a
session blob received from a client (e.g. an HTTP cookie or a network frame),
which makes this an ``network`` / ``library`` exposure target.
"""

from __future__ import annotations

import pickle
from dataclasses import dataclass
from typing import Any

__all__ = ["Session", "load_session", "dump_session"]


@dataclass
class Session:
    user_id: str
    role: str
    data: Any = None


def dump_session(session: Session) -> bytes:
    """Serialize a Session to bytes (legitimate producer-side helper)."""
    return pickle.dumps(session)


def load_session(blob: bytes) -> Session:
    """Decode a session blob received from an untrusted client.

    Bug: ``pickle.loads`` will execute any ``__reduce__`` gadget the attacker
    embeds. The fix is to switch to a signed JSON envelope or to validate the
    blob with ``hmac.compare_digest`` *before* unpickling.
    """
    obj = pickle.loads(blob)
    if not isinstance(obj, Session):
        raise TypeError(f"expected Session, got {type(obj).__name__}")
    return obj
