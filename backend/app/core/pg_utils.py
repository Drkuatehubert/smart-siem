from __future__ import annotations

import ipaddress
from datetime import date, datetime
from uuid import UUID


def serialize_row(row) -> dict:
    out: dict = {}
    for key, value in dict(row).items():
        if isinstance(value, (datetime, date)):
            out[key] = value.isoformat()
        elif isinstance(value, UUID):
            out[key] = str(value)
        elif isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            out[key] = str(value)
        else:
            out[key] = value
    return out
