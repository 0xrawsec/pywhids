#!/usr/bin/env python
# fixing pywhids import if not installed
import imports

import os
import sys
import toml
import time
import asyncio
import urllib3
import argparse
import ipaddress

from typing import *
from datetime import date, datetime, timezone, timedelta

from pymisp import PyMISP, MISPEvent, MISPAttribute

from pywhids.client import Client
from pywhids.ioc import IOC

ALLOWED_TYPES = set([
    "md5",
    "sha1",
    "sha256",
    "domain",
    "hostname",
    "ip-dst",
])

def print_stderr(msg: str):
    print(msg, file=sys.stderr)

def uuids_from_search(search):
    uuids = []
    for res in search:
        if isinstance(res, dict):
            uuids.append(res["uuid"])
        else:
            uuids.append(res.uuid)
    return uuids

def iocs_from_attributes(source: str, uuid: str, attributes: List[MISPAttribute]) -> List[IOC]:
    iocs = []
    for a in attributes:
        if a.type in ALLOWED_TYPES:
            iocs.append(IOC(uuid=a.uuid, guuid=uuid, source=source, value=a.value, type=a.type))
    return iocs

def ioc_from_attribute(attr, source=""):
    return IOC(uuid=attr.uuid, guuid=attr.event_uuid, source=source, value=attr.value, type=attr.type)


def emit_attributes(misp: PyMISP, uuids: List[str]):
    for uuid in uuids:
        event = misp.get_event(uuid, pythonify=True)
        for attr in event.attributes:
            attr.event_uuid = uuid
            yield attr
        for o in event.objects:
            for attr in o.attributes:
                attr.event_uuid = uuid
                yield attr

def sync_iocs(misp: PyMISP, whids: Client, source:str, since: date, all: bool):
    to_add = []
    to_del = []

    published = True if not all else None
    # search events to pull attributes from
    if since == None:
        index = misp.search_index(published=published)
    else:
        index = misp.search_index(published=published, timestamp=since)

    for attr in emit_attributes(misp, uuids_from_search(index)):
        if since is not None:
            if attr.timestamp.date() < since:
                continue
        if attr.to_ids and attr.type in ALLOWED_TYPES:
            ioc = ioc_from_attribute(attr, source=args.source)
            print_stderr(f"+ {ioc}")
            to_add.append(ioc)
        elif attr.type in ALLOWED_TYPES:
            ioc = ioc_from_attribute(attr, source=args.source)
            print_stderr(f"- {ioc}")
            to_del.append(ioc)
    
    whids.delete_iocs(to_del) 
    whids.add_iocs(to_add) 


if __name__ == "__main__":

    default_config = os.path.realpath(os.path.join(
        os.path.dirname(__file__), "config.toml"))

    parser = argparse.ArgumentParser(
        description="Plugin to create MISP objects from WHIDS detection reports")
    parser.add_argument("-c", "--config", default=default_config,
                        type=str, help=f"Configuration file. Default: {default_config}")
    parser.add_argument("-s", "--silent", action="store_true",
                        help="Silent HTTPS warnings")
    parser.add_argument("-l", "--last", type=int, default=1,
                        help="Process events updated the last days")
    parser.add_argument("--all", action="store_true",
                        help="Process all events, published and unpublished. By default only published events are processed.")
    parser.add_argument("--service", action="store_true",
                        help="Run in service mode (i.e endless loop)")
    parser.add_argument("--source", type=str,
                        help="Name of the IOC source")

    args = parser.parse_args()

    # silent https warnings
    if args.silent:
        urllib3.disable_warnings()

    config = toml.load(open(args.config))

    misp_config = config["misp"]
    whids = Client(**config["whids"])
    misp = PyMISP(url=misp_config["url"], key=misp_config["key"], ssl=misp_config["ssl"])

    # handling last option
    since = None
    if args.last is not None:
        since = (datetime.now() - timedelta(days=args.last)).date()
    
    # handling source option
    if args.source is None:
        args.source = misp_config["name"]

    while True:
        sync_iocs(misp, whids, args.source, since, args.all)
        if args.service:
            time.sleep(60)
        else:
            break