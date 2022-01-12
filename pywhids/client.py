import json
import typing
import requests
import time

from datetime import datetime, timezone

from .exceptions import *
from .artifacts import *
from .event import Event
from .endpoint import Endpoint
from .ioc import IOC


def api_timestamp(t: datetime):
    if t.tzinfo is None:
        t.replace(tzinfo=timezone.utc)
    return t.isoformat(timespec="seconds") + "Z"


class Client(requests.Session):

    def __init__(self, url: str, key: str, verify=True):
        # initialize session
        super().__init__()

        self._url = url
        self._key = key
        self.verify = verify

        # creating session
        self.headers = {
            "X-Api-key": self._key,
        }

    def _api_route(self, path: str):
        surl = self._url.rstrip('/')
        spath = path.lstrip('/')
        return f"{surl}/{spath}"

    def _request(self, *args, **kwargs) -> dict:
        resp = self.request(*args, **kwargs)
        if resp.status_code == 200:
            d = resp.json()
            if d["error"] != "":
                raise APIError(d["error"])
            return d["data"]
        raise UnexpectedStatusError(resp.status_code)

    def endpoint(self, uuid):
        route = self._api_route(f"/endpoints/{uuid}")
        return Endpoint(self, self._request("GET", route))

    def artifacts(self, since=None) -> typing.Generator[EventArtifacts, None, None]:
        route = self._api_route("/endpoints/artifacts")
        params = {}
        if since != None:
            if isinstance(since, datetime):
                params = {"since": api_timestamp(since)}

        d = self._request("GET", route, params=params)
        for uuid in d:
            for art_data in d[uuid]:
                yield EventArtifacts(self, uuid, art_data)
    
    def get_iocs(self):
        route = self._api_route("/iocs")

        params = {}

        d = self._request("GET", route, params=params)
        for ioc_data in d:
            yield IOC(**ioc_data)    

    def add_iocs(self, iocs: typing.Union[IOC, typing.Iterator[IOC]]):
        route = self._api_route("/iocs")

        if isinstance(iocs, IOC):
            iocs = [iocs]

        iocs = list(map(lambda x: x.to_dict(), iocs))

        self._request("POST", route, json=iocs)

    def delete_iocs(self, iocs: typing.Union[IOC, typing.Iterator[IOC]]) -> IOC:
        route = self._api_route("/iocs")

        if isinstance(iocs, IOC):
            iocs = [iocs]
        
        for ioc in iocs:
            params = {"uuid": ioc.uuid}
            d = self._request("DELETE", route, params=params)
