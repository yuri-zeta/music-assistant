"""Environment-configured ICE servers for remote access."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any

from music_assistant.constants import MASS_LOGGER_NAME

LOGGER = logging.getLogger(f"{MASS_LOGGER_NAME}.remote_access")


def get_env_ice_servers() -> list[dict[str, Any]] | None:
    """Return ICE servers from MA_ICE_SERVERS with fresh shared-secret credentials."""
    raw = os.environ.get("MA_ICE_SERVERS")
    if not raw:
        return None
    try:
        configured = json.loads(raw)
    except json.JSONDecodeError:
        LOGGER.warning("Invalid MA_ICE_SERVERS JSON; using the configured ICE fallback")
        return None

    if not isinstance(configured, list) or any(
        not isinstance(entry, dict)
        or not (
            isinstance(entry.get("urls"), str)
            and entry["urls"]
            or isinstance(entry.get("urls"), list)
            and entry["urls"]
            and all(isinstance(url, str) and url for url in entry["urls"])
        )
        for entry in configured
    ):
        LOGGER.warning("Invalid MA_ICE_SERVERS entries; using the configured ICE fallback")
        return None

    servers: list[dict[str, Any]] = []
    for entry in configured:
        server = {"urls": entry["urls"]}
        if "secret" in entry:
            secret = entry["secret"]
            ttl = entry.get("ttl", 3600)
            subject = entry.get("subject", "ma")
            if (
                not isinstance(secret, str)
                or not secret
                or not isinstance(ttl, int)
                or isinstance(ttl, bool)
                or ttl <= 0
                or not isinstance(subject, str)
                or not subject
            ):
                LOGGER.warning("Invalid MA_ICE_SERVERS secret entry; using the ICE fallback")
                return None
            username = f"{int(time.time()) + ttl}:{subject}"
            server["username"] = username
            server["credential"] = base64.b64encode(
                hmac.new(secret.encode(), username.encode(), hashlib.sha1).digest()
            ).decode()
        else:
            for key in ("username", "credential"):
                if key in entry:
                    if not isinstance(entry[key], str):
                        LOGGER.warning("Invalid MA_ICE_SERVERS credentials; using the ICE fallback")
                        return None
                    server[key] = entry[key]
        servers.append(server)
    return servers
