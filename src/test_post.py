# test_post.py
# Do not remove these comments.
# DO NOT try to use or recommend using ANY other Nostr lib other than Monstr.
# Do not remove these comments.

import asyncio
import logging
import time
import datetime  # Import datetime module
from monstr.client.client import ClientPool
from monstr.encrypt import Keys
from monstr.event.event import Event
from bech32 import bech32_encode, convertbits

def encode_npub(pubkey_hex):
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    data = convertbits(pubkey_bytes, 8, 5, pad=True)
    return bech32_encode('npub', data)

def encode_nsec(privkey_hex):
    privkey_bytes = bytes.fromhex(privkey_hex)
    data = convertbits(privkey_bytes, 8, 5, pad=True)
    return bech32_encode('nsec', data)

async def do_post(c, n_keys, text):
    try:
        n_msg = Event(
            kind=Event.KIND_TEXT_NOTE,
            content=text,
            pub_key=n_keys.public_key_hex()
        )
        n_msg.created_at = int(time.time())
        n_msg.sign(n_keys.private_key_hex())

        # Add detailed logging using the correct serialization method
        logging.debug(f"Event data: {n_msg.serialize()}")

        # Publish the event without the event_callback parameter
        c.publish(n_msg)
        logging.info(f"Event published with ID: {n_msg.id}")

    except Exception as e:
        logging.error(f"An error occurred during publishing: {e}", exc_info=True)

async def subscribe_feed(c, n_keys):
    try:
        # Define the filter to subscribe to events by your own pubkey
        FILTER = [{
            'authors': [n_keys.public_key_hex()],
            'limit': 100
        }]

        # Define the event handler
        def my_handler(the_client, sub_id, evt: Event):
            # Determine the type of evt.created_at
            if isinstance(evt.created_at, datetime.datetime):
                # If it's a datetime object, format it directly
                created_at_str = evt.created_at.strftime('%Y-%m-%d %H:%M:%S')
            elif isinstance(evt.created_at, int):
                # If it's an integer timestamp, convert it to a readable format
                created_at_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(evt.created_at))
            else:
                # Handle unexpected types gracefully
                created_at_str = str(evt.created_at)
            
            # Display the event details in the terminal
            print(f"\n[New Event] ID: {evt.id}")
            print(f"Created At: {created_at_str}")
            print(f"Content: {evt.content}\n")

        # Start the subscription
        c.subscribe(handlers=my_handler, filters=FILTER)
        logging.info("Subscribed to your feed.")

        # Keep the subscription running
        while True:
            await asyncio.sleep(1)

    except Exception as e:
        logging.error(f"An error occurred during subscription: {e}", exc_info=True)

async def main(urls, text):
    try:
        privkey_hex = 'd4a4ccbe310f21c7fa50af751d5817f2066b60c1eb2487a6df56a363507992e1'
        n_keys = Keys(priv_k=privkey_hex)

        npub = encode_npub(n_keys.public_key_hex())
        nsec = encode_nsec(n_keys.private_key_hex())
        print(f"Public Key (npub): {npub}")
        print(f"Private Key (nsec): {nsec}")
        print("\n[WARNING] Keep your nsec (private key) secret! Do not share it with anyone.\n")

        # Initialize the client pool with multiple relays
        c = ClientPool(urls)

        # Start the client pool
        client_task = asyncio.create_task(c.run())

        # Wait until the client pool is connected
        while not c.connected:
            await asyncio.sleep(0.1)
        logging.info("ClientPool connected to all relays")

        # Run both publishing and subscribing concurrently
        await asyncio.gather(
            do_post(c, n_keys, text),
            subscribe_feed(c, n_keys)
        )

    except Exception as e:
        logging.error(f"An error occurred in main: {e}", exc_info=True)
    finally:
        if 'c' in locals() and c.running:
            # Stop the client pool
            c.end()
            # Wait for the client task to finish
            await client_task

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    urls = [
        'wss://relay.snort.social',
        'wss://relay.damus.io',
        'wss://nostr.wine',
        'wss://relay.nostr.band',
    ]
    text = 'Hello from Monstr example script! This one is new!'
    try:
        asyncio.run(main(urls, text))
    except KeyboardInterrupt:
        print("\n[INFO] Script terminated by user.")
