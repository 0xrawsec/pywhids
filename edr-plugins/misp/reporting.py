#!/usr/bin/env python

# fixing pywhids imports
import imports

import os
import io
import sys
import json
import toml
import typing
import urllib3
import pywhids
import time
import argparse

from pymisp import PyMISP, MISPEvent, MISPObject
from datetime import datetime, timedelta

EDR_PRODUCT = "WHIDS"


def pretty_json(data) -> str:
    return json.dumps(data, indent="  ")


def prepare_json_misp(data) -> io.BytesIO:
    return io.BytesIO(bytes(pretty_json(data), encoding="utf8"))


def misp_event_name(timestamp: datetime) -> str:
    return "EDR detection reports collected on {}".format(timestamp.strftime("%Y-%m-%d"))


def log_stderr(message):
    print(message, file=sys.stderr)


class MISPEDRDetectionReporter():

    def __init__(self, misp: PyMISP, edr_client: pywhids.Client):
        self._misp = misp
        self._edr_client = edr_client

    def _get_or_create_event(self, timestamp: datetime) -> typing.Tuple[MISPEvent, bool]:
        name = misp_event_name(timestamp)
        exists = False
        sr = self._misp.search_index(
            eventinfo=name, pythonify=True)
        if len(sr) == 0:
            event = MISPEvent()
            event.info = name
            return event, exists
        exists = True
        return self._misp.get_event(sr[0].uuid, pythonify=True), exists

    def import_edr_report(self, since: datetime):

        for evt_art in c.artifacts(since):

            if evt_art.event is None:
                log_stderr(
                    f"Event is missing endpoint={evt_art.endpoint.uuid}")
                continue

            if evt_art.has_report():
                # retrieving MISP event
                misp_event, exists = self._get_or_create_event(
                    evt_art.creation)

                # building up a list of already processed reports
                already_proc_report_ids = set()
                # for obj in [o for o in misp_event.objects if o.name == "edr-report"]:
                for obj in filter(lambda o: o.name == "edr-report", misp_event.objects):
                    for attr in obj.attributes:
                        if attr.object_relation == "id":
                            already_proc_report_ids.add(attr.value)
                            break

                if evt_art.event_hash not in already_proc_report_ids:
                    log_stderr(
                        f"Processing event={evt_art.event_hash} endpoint={evt_art.endpoint.uuid}")

                    # creating a new MISP report object
                    report_obj = MISPObject("edr-report")
                    # setting the timestamp of the object
                    report_obj.first_seen = evt_art.event.timestamp
                    # unique identifer of the report
                    report_obj.add_attribute(
                        "id", evt_art.event_hash, comment="Unique event identifier")
                    # unique identifier of the endpoint
                    report_obj.add_attribute(
                        "endpoint-id", evt_art.endpoint.uuid, comment="Unique endpoint identifier")

                    # setting up endpoint IP address
                    if evt_art.endpoint.ip_address != "":
                        report_obj.add_attribute(
                            "ip", evt_art.endpoint.ip_address, comment="Endpoint IP address", to_ids=False)

                    # setting endpoint hostname
                    if evt_art.endpoint.hostname != "":
                        report_obj.add_attribute(
                            "hostname", evt_art.endpoint.hostname, comment="Endpoint hostname", to_ids=False)

                    str_sig = ",".join(evt_art.event.signature)
                    if str_sig != "":
                        report_obj.add_attribute(
                            "comment", f"Event triggering {str_sig} caught on endpoint")

                    # setting EDR product
                    report_obj.add_attribute(
                        "product", EDR_PRODUCT, comment="EDR product name")
                    # adding triggering event
                    report_obj.add_attribute(
                        "event", "event.json", comment="Report generation trigger", data=prepare_json_misp(evt_art.event.data))

                    # adding information about loaded drivers and running processes
                    edr_report = evt_art.report

                    if "processes" in edr_report:
                        report_obj.add_attribute(
                            "processes", "processes.json", comment="Running process snapshot at detection time", data=prepare_json_misp(edr_report["processes"]))

                    if "modules" in edr_report:
                        report_obj.add_attribute(
                            "modules", "modules.json", comment="Ever loaded modules since boot until detection time", data=prepare_json_misp(edr_report["modules"]))

                    if "drivers" in edr_report:
                        report_obj.add_attribute(
                            "drivers", "drivers.json", comment="Ever loaded drivers since boot until detection time", data=prepare_json_misp(edr_report["drivers"]))

                    # adding any command ran at report generation
                    if "commands" in edr_report:
                        if edr_report["commands"] is not None:
                            for com in edr_report["commands"]:
                                report_obj.add_attribute(
                                    "command", "command.json", comment=com["description"], data=prepare_json_misp(com))

                    # adding any interesting file dumped
                    for art in evt_art.artifacts_excl_report_event():
                        if art.is_filedump():
                            if art.original_ext == ".exe":
                                report_obj.add_attribute(
                                    "executable",
                                    art.original_name,
                                    comment="Executable file involved in detection",
                                    data=io.BytesIO(art.content)
                                )
                            else:
                                report_obj.add_attribute(
                                    "additional-file",
                                    art.original_name,
                                    comment="Additional file involved in detection",
                                    data=io.BytesIO(art.content)
                                )

                    # adding report object to the MISP event
                    misp_event.add_object(report_obj)

                    # commiting the changes to MISP instance
                    if not exists:
                        self._misp.add_event(misp_event)
                    else:
                        self._misp.update_event(misp_event)


if __name__ == "__main__":

    default_config = os.path.realpath(os.path.join(
        os.path.dirname(__file__), "config.toml"))

    parser = argparse.ArgumentParser(
        description="Plugin to create MISP objects from WHIDS detection reports")
    parser.add_argument("-c", "--config", default=default_config,
                        type=str, help=f"Configuration file. Default: {default_config}")
    parser.add_argument("-s", "--silent", action="store_true",
                        help="Silent HTTPS warnings")
    parser.add_argument("-l", "--last", default=1, type=float,
                        help="Process reports generated the last days. Default: 1 day")
    parser.add_argument("--service", action="store_true",
                        help="Run in service mode (i.e endless loop)")

    args = parser.parse_args()

    # silent https warnings
    if args.silent:
        urllib3.disable_warnings()

    config = toml.load(open(args.config))

    c = pywhids.Client(**config["whids"])
    misp = PyMISP(**config["misp"])

    while True:
        MISPEDRDetectionReporter(misp, c).import_edr_report(
            datetime.now()-timedelta(days=args.last))
        if not args.service:
            break
        time.sleep(60)
