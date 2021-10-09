#!/usr/bin/env python
# fixing pywhids import if not installed
import imports

import os
import sys
import toml
import asyncio
import urllib3
import argparse
import ipaddress

from typing import *
from datetime import datetime, timezone, timedelta

from pymisp import PyMISP

from pywhids.event import Event, parse_sysmon_hashes
from pywhids.client import Client
from pywhids.streams import EventStream

PATH_EVENT_DATA = "/Event/EventData"

# Sysmon field paths
SYSMON_PATH_HASHES = PATH_EVENT_DATA + "/Hashes"
SYSMON_PATH_IMAGE = PATH_EVENT_DATA + "/Image"
SYSMON_PATH_SOURCE_IMAGE = PATH_EVENT_DATA + "/SourceImage"
SYSMON_PATH_IMAGE_LOADED = PATH_EVENT_DATA + "/ImageLoaded"
SYSMON_PATH_PARENT_IMAGE = PATH_EVENT_DATA + "/ParentImage"
SYSMON_PATH_ORIGINAL_FILENAME = PATH_EVENT_DATA + "/OriginalFileName"
SYSMON_PATH_TARGET_FILENAME = PATH_EVENT_DATA + "/TargetFilename"
SYSMON_PATH_DESTINATION_HOSTNAME = PATH_EVENT_DATA + "/DestinationHostname"
SYSMON_PATH_DESTINATION_IP = PATH_EVENT_DATA + "/DestinationIp"
SYSMON_PATH_DESTINATION_IPV6 = PATH_EVENT_DATA + "/DestinationIpv6"
SYSMON_PATH_SOURCE_HOSTNAME = PATH_EVENT_DATA + "/SourceHostname"
SYSMON_PATH_SOURCE_IP = PATH_EVENT_DATA + "/SourceIp"
SYSMON_PATH_SOURCE_IPV6 = PATH_EVENT_DATA + "/SourceIpv6"
SYSMON_PATH_TARGET_OBJECT = PATH_EVENT_DATA + "/TargetObject"
SYSMON_PATH_PIPE_NAME = PATH_EVENT_DATA + "/PipeName"
SYSMON_PATH_QUERY_NAME = PATH_EVENT_DATA + "/QueryName"
SYSMON_PATH_QUERY_RESULTS = PATH_EVENT_DATA + "/QueryResults"


EDR_PATH_IMAGE_HASHES = PATH_EVENT_DATA + "/ImageHashes"
EDR_PATH_SOURCE_HASHES = PATH_EVENT_DATA + "/SourceHashes"

EDR_PATH_ENDPOINT = "/Event/EdrData/Endpoint"
EDR_PATH_ENDPOINT_UUID = EDR_PATH_ENDPOINT + "/UUID"
EDR_PATH_ENDPOINT_HOSTNAME = EDR_PATH_ENDPOINT + "/Hostname"

SIGHTINGS_PATHS = [
    SYSMON_PATH_HASHES,
    SYSMON_PATH_IMAGE,
    SYSMON_PATH_SOURCE_IMAGE,
    SYSMON_PATH_IMAGE_LOADED,
    SYSMON_PATH_PARENT_IMAGE,
    SYSMON_PATH_ORIGINAL_FILENAME,
    SYSMON_PATH_TARGET_FILENAME,
    SYSMON_PATH_DESTINATION_HOSTNAME,
    SYSMON_PATH_DESTINATION_IP,
    SYSMON_PATH_DESTINATION_IPV6,
    SYSMON_PATH_SOURCE_HOSTNAME,
    SYSMON_PATH_SOURCE_IP,
    SYSMON_PATH_SOURCE_IPV6,
    SYSMON_PATH_TARGET_OBJECT,
    SYSMON_PATH_PIPE_NAME,
    SYSMON_PATH_QUERY_NAME,
    SYSMON_PATH_QUERY_RESULTS,
    EDR_PATH_IMAGE_HASHES,
    EDR_PATH_SOURCE_HASHES,
]


class SightCache():

    def __init__(self):
        self._cache = {}

    def update(self, source: str, sightings: list):
        if source not in self._cache:
            self._cache[source] = {}
        source_cache = self._cache[source]
        for s in sightings:
            source_cache[s] = datetime.now()

    def filter(self, source: str, sightings: list, delta: timedelta):
        if source not in self._cache:
            return sightings
        out = []
        now = datetime.now()
        source_cache = self._cache[source]
        for s in sightings:
            if s in source_cache:
                if now - source_cache[s] > delta:
                    out.append(s)
            else:
                out.append(s)
        return out


class SightingsUpdater(EventStream):

    def __init__(self, edr_cl: Client, misp_cl: PyMISP, cache_ttl=timedelta(minutes=1)):
        # init EventStream
        super().__init__(edr_cl)
        self._edr = edr_cl
        self._misp = misp_cl
        self._cache = SightCache()
        self._cache_ttl = cache_ttl

    def sysmon_sightings(self, event: Event) -> List[Any]:
        s = []

        for p in SIGHTINGS_PATHS:
            v = event.get(p)
            if v is None:
                # if the path does not exist we continue
                continue
            if p in [SYSMON_PATH_HASHES, EDR_PATH_IMAGE_HASHES, EDR_PATH_SOURCE_HASHES]:
                # if it is on field with hashes information we need a bit of processing first
                for h in parse_sysmon_hashes(v).values():
                    s.append(h)
                continue
            if p in [SYSMON_PATH_DESTINATION_HOSTNAME, SYSMON_PATH_SOURCE_HOSTNAME]:
                # default value when hostname is unknown
                if v != "-":
                    s.append(v)
                continue
            if p == SYSMON_PATH_QUERY_RESULTS:
                for ip in v.split(";"):
                    # we try to parse IP addresses
                    try:
                        s.append(str(ipaddress.ip_address(ip)))
                    except ValueError:
                        pass
                continue

            # default we append value as is
            s.append(v)

        return s

    def on_event(self, event: Event):
        sightings = []
        uuid = event.get(EDR_PATH_ENDPOINT_UUID)
        hostname = event.get(EDR_PATH_ENDPOINT_HOSTNAME)
        source = f"{uuid}|{hostname}"

        if event.channel == "Microsoft-Windows-Sysmon/Operational":
            sightings += self.sysmon_sightings(event)

        # we removed sightings added in the last minute
        sightings = self._cache.filter(
            source, sightings, self._cache_ttl)

        if len(sightings):
            sighting_obj = {
                "values": list(sightings),
                "filters": {"to_ids": 1},
                "source": source,
            }
            print(f"Updating source={source} sightings={sightings}")
            self._misp.add_sighting(sighting_obj)
            self._cache.update(source, sightings)


if __name__ == "__main__":

    default_config = os.path.realpath(os.path.join(
        os.path.dirname(__file__), "config.toml"))

    parser = argparse.ArgumentParser(
        description="Plugin to add MISP sightings from EDR logs")
    parser.add_argument("--config", default=default_config,
                        type=str, help=f"Configuration file. Default: {default_config}")
    parser.add_argument("-s", "--silent", action="store_true",
                        help="Silent HTTPS warnings")
    parser.add_argument("-v", "--verbose", help="Prints out sightings added")
    parser.add_argument(
        "--cache-ttl", default=1, help="How long (in minutes) a sighting must live in \
            cache before being updated. The bigger this parameter, the less \
            updates for a given sighting. Increasing this parameter can help handling a higher \
            event throughput. Default: 1 minute")

    args = parser.parse_args()

    config = toml.load(open(args.config))

    if args.silent:
        urllib3.disable_warnings()

    c = Client(**config["whids"])
    misp = PyMISP(**config["misp"])

    s = SightingsUpdater(c, misp, timedelta(args.cache_ttl))
    asyncio.run(s.run(False))
