import ssl
import json
import time
import typing
import asyncio
import requests
import logging
import websockets

from .client import Client
from .event import Event


class BaseStream():

    def __init__(self, client: Client, route: str):
        self._client = client
        self._route = route
        self._count = 0
        self._queue = asyncio.Queue()

    def _wait_connect(self):

        url = self._client._api_route("")

        while True:
            try:
                self._client.get(url)
                break
            except requests.exceptions.ConnectionError:
                time.sleep(0.2)

    async def _produce(self, queue: asyncio.Queue):
        kwargs = {}
        if not self._client.verify:
            kwargs["ssl"] = ssl._create_unverified_context()

        url = self._client._api_route(self._route).replace("http", "ws", 1)

        async with websockets.connect(url, extra_headers={"Api-Key": self._client._key}, ping_interval=1, ping_timeout=None, ** kwargs) as ws:
            while True:
                b = await ws.recv()
                # await self.on_event(Event(json.loads(b)))

                await queue.put(Event(json.loads(b)))
                self._count += 1

    async def _produce_forever(self, q: asyncio.Queue, wait=True):
        while True:
            try:
                if wait:
                    self._wait_connect()
                # asyncio.run(self.run(wait))
                await self._produce(q)
            except websockets.exceptions.ConnectionClosedError as e:
                print(f"Websocket connection closed: {e}")

    def _consume(self, queue: asyncio.Queue):
        while True:
            try:
                e = queue.get_nowait()
                self.on_event(e)
            except asyncio.queues.QueueEmpty:
                time.sleep(1)

    async def run(self, wait=True):
        q = asyncio.Queue()
        p = asyncio.create_task(self._produce_forever(q))
        c = asyncio.to_thread(self._consume, q)
        await asyncio.gather(p, c)

    def on_event(self, event: Event):
        raise NotImplementedError


class EventStream(BaseStream):

    def __init__(self, client: Client):
        super().__init__(client, "/stream/events")


class DetectionStream(BaseStream):

    def __init__(self, client: Client):
        super().__init__(client, "/stream/detections")
