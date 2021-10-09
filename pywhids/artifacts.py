import re
import os
import json
import typing

from .utils import *
from .exceptions import *
from .event import Event
from .endpoint import Endpoint


class Artifact():

    def __init__(self, client, endpoint_uuid: str, url: str, name: str, size: int, timestamp: str):
        self._client = client
        self._endpoint_uuid = endpoint_uuid
        self._url = url
        self._name = name
        self._size = size
        self._timestamp = timestamp
        self._path = f"{url}/{name}"

    @property
    def path(self) -> str:
        return self._path

    @property
    def name(self) -> str:
        return self._name

    @property
    def original_name(self) -> str:
        f = removesuffix(removesuffix(self.name, ".gz"), ".bin")
        return f.split("_", 1)[1]

    @property
    def original_ext(self) -> str:
        f = removesuffix(removesuffix(self.name, ".gz"), ".bin")
        return os.path.splitext(f)[1]

    def __str__(self) -> str:
        return f"uuid:{self._endpoint_uuid} name:{self.name}"

    @property
    def content(self) -> bytes:
        url = self._client._api_route(self.path)
        gunzip = self._name.endswith(".gz")
        resp = self._client.get(url, params={"raw": True, "gunzip": gunzip})
        if resp.status_code == 200:
            return resp.content
        raise UnexpectedStatusError(resp.status_code)

    def is_filedump(self) -> bool:
        return self.name.endswith(".bin") or self.name.endswith(".bin.gz")


class EventArtifacts():

    def __init__(self, client, uuid: str, data: dict):
        self._client = client
        self._uuid = uuid
        self._data = data
        self._endpoint = None

    @property
    def creation(self) -> datetime:
        return parse_rfc3339_nano_timestamp(self._data["creation"])

    @property
    def event_hash(self) -> str:
        return self._data["event-hash"]

    @property
    def endpoint(self) -> Endpoint:
        if self._endpoint == None:
            self._endpoint = self._client.endpoint(self._uuid)
        return self._endpoint

    @property
    def filenames(self) -> typing.List[str]:
        return [f["name"] for f in self._data["files"]]

    @property
    def event(self) -> Event:
        basename = "event.json"
        for f in [basename, f"{basename}.gz"]:
            if self._has_file(f):
                return Event(json.loads(self.artifact(f).content))

    @property
    def report(self) -> dict:
        basename = "report.json"
        for f in [basename, f"{basename}.gz"]:
            if self._has_file(f):
                return json.loads(self.artifact(f).content)

    def __str__(self) -> str:
        return str(self._data)

    def _has_file(self, name: str) -> bool:
        return name in self.filenames

    def _file(self, name: str) -> typing.Union[dict, None]:
        for f in self._data["files"]:
            if f["name"] == name:
                return f

    def artifact(self, name: str) -> typing.Union[Artifact, None]:
        if self._has_file(name):
            f = self._file(name)
            fname, size, timestamp = f["name"], f["size"], f["timestamp"]
            return Artifact(self._client, self._uuid, self._data["base-url"], fname, size, timestamp)

    def has_report(self) -> bool:
        return self._has_file("report.json.gz") or self._has_file("report.json")

    def artifacts_excl_report_event(self) -> typing.Generator[Artifact, None, None]:
        return self.artifacts(r"(^(report|event)\.json(\.gz)?$)", exclude=True)

    def artifacts(self, pattern=".*", exclude=False) -> typing.Generator[Artifact, None, None]:
        pat = re.compile(pattern)
        for f in self._data["files"]:
            fname, size, timestamp = f["name"], f["size"], f["timestamp"]
            if pat.search(fname) is not None and not exclude:
                yield Artifact(self._client, self._uuid, self._data["base-url"], fname, size, timestamp)
            elif pat.search(fname) is None and exclude:
                yield Artifact(self._client, self._uuid, self._data["base-url"], fname, size, timestamp)
