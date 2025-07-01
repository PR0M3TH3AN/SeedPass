import asyncio
import json
import threading
import time
from websocket import create_connection

import websockets
from nostr.key_manager import KeyManager
from pynostr.event import Event, EventKind


class FakeRelay:
    def __init__(self):
        self.events = []

    async def handler(self, ws):
        async for message in ws:
            data = json.loads(message)
            if data[0] == "EVENT":
                event = data[1]
                self.events.append(event)
                await ws.send(json.dumps(["OK", event["id"], True, ""]))
            elif data[0] == "REQ":
                sub_id = data[1]
                for event in self.events:
                    await ws.send(json.dumps(["EVENT", sub_id, event]))
                await ws.send(json.dumps(["EOSE", sub_id]))


def run_relay(relay, host="localhost", port=8765):
    async def main():
        async with websockets.serve(relay.handler, host, port):
            await asyncio.Future()

    asyncio.run(main())


def test_pynostr_send_receive(tmp_path):
    relay = FakeRelay()
    thread = threading.Thread(target=run_relay, args=(relay,), daemon=True)
    thread.start()

    time.sleep(0.5)

    seed = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    fingerprint = "test"
    km = KeyManager(seed, fingerprint)

    ws = create_connection("ws://localhost:8765")

    event = Event(kind=EventKind.TEXT_NOTE, content="hello")
    event.pubkey = km.get_public_key_hex()
    event.created_at = int(time.time())
    event.sign(km.get_private_key_hex())

    ws.send(event.to_message())
    sub_id = "1"
    ws.send(json.dumps(["REQ", sub_id, {}]))

    received = None
    while True:
        msg = json.loads(ws.recv())
        if msg[0] == "EVENT":
            received = msg[2]
        elif msg[0] == "EOSE":
            break
    ws.close()

    assert received is not None
    assert received["content"] == "hello"
