import json
import typing

from datetime import datetime, timezone

from .utils import *


def parse_sysmon_hashes(hashes: str) -> typing.Dict:
    d = {}
    if isinstance(hashes, str):
        for h in hashes.split(","):
            if "=" in h:
                name, value = h.split("=")
                d[name.lower()] = value.lower()
    return d


class Event():

    def __init__(self, data):
        self._data = data

    @property
    def channel(self) -> str:
        return self.get("/Event/System/Channel")

    @property
    def event_id(self) -> int:
        return self.get("/Event/System/EventID")

    @property
    def json(self) -> str:
        return json.dumps(self._data)

    @property
    def data(self) -> str:
        return self._data

    @property
    def timestamp(self) -> datetime:
        timestamp = self.get("/Event/System/TimeCreated/SystemTime")
        return parse_rfc3339_nano_timestamp(timestamp)

    @property
    def signature(self) -> typing.List[str]:
        return self.get("/Event/Detection/Signature")

    def __str__(self):
        return str(self._data)

    def _get(self, data, path: typing.List[str]):
        if len(path) > 0:
            if len(path) == 1:
                if path[0] in data:
                    return data[path[0]]
                return None
            elif path[0] in data:
                new = data[path[0]]
                if isinstance(new, dict):
                    return self._get(new, path[1:])

    def get(self, path: str):
        return self._get(self._data, path.lstrip("/").split("/"))
