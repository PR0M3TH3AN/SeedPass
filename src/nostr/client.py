# nostr/client.py

import os
import sys
import logging
import traceback
import json
import time
import base64
import hashlib
import asyncio
import concurrent.futures
from typing import List, Optional, Callable

from monstr.client.client import ClientPool
from monstr.encrypt import Keys, NIP4Encrypt
from monstr.event.event import Event

import threading
import uuid
import fcntl  # Ensure fcntl is imported for file locking

from .logging_config import configure_logging
from .key_manager import KeyManager
from .encryption_manager import EncryptionManager
from .event_handler import EventHandler
from constants import APP_DIR, INDEX_FILE, DATA_CHECKSUM_FILE
from utils.file_lock import lock_file

configure_logging()
logger = logging.getLogger(__name__)

DEFAULT_RELAYS = [
    "wss://relay.snort.social",
    "wss://nostr.oxtr.dev",
    "wss://nostr-relay.wlvs.space"
]

class NostrClient:
    """
    NostrClient Class

    Handles interactions with the Nostr network, including publishing and retrieving encrypted events.
    Utilizes deterministic key derivation via BIP-85 and integrates with the monstr library for protocol operations.
    """

    def __init__(self, parent_seed: str, relays: Optional[List[str]] = None):
        """
        Initializes the NostrClient with a parent seed and connects to specified relays.

        :param parent_seed: The BIP39 mnemonic seed phrase.
        :param relays: (Optional) A list of relay URLs to connect to. Defaults to predefined relays.
        """
        try:
            self.key_manager = KeyManager(parent_seed)
            self.encryption_manager = EncryptionManager(self.key_manager)
            self.event_handler = EventHandler()

            self.relays = relays if relays else DEFAULT_RELAYS
            self.client_pool = ClientPool(self.relays)
            self.subscriptions = {}

            self.initialize_client_pool()
            logger.info("NostrClient initialized successfully.")

            self.is_shutting_down = False
            self._shutdown_event = asyncio.Event()

        except Exception as e:
            logger.error(f"Initialization failed: {e}")
            logger.error(traceback.format_exc())
            print(f"Error: Initialization failed: {e}", file=sys.stderr)
            sys.exit(1)

    def initialize_client_pool(self):
        """
        Initializes the ClientPool with the specified relays in a separate thread.
        """
        try:
            logger.debug("Initializing ClientPool with relays.")
            self.client_pool = ClientPool(self.relays)

            # Start the ClientPool in a separate thread
            self.loop_thread = threading.Thread(target=self.run_event_loop, daemon=True)
            self.loop_thread.start()

            # Wait until the ClientPool is connected to all relays
            self.wait_for_connection()

            logger.info("ClientPool connected to all relays.")
        except Exception as e:
            logger.error(f"Failed to initialize ClientPool: {e}")
            logger.error(traceback.format_exc())
            print(f"Error: Failed to initialize ClientPool: {e}", file=sys.stderr)
            sys.exit(1)

    def run_event_loop(self):
        """
        Runs the event loop for the ClientPool in a separate thread.
        """
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.create_task(self.client_pool.run())
            self.loop.run_forever()
        except asyncio.CancelledError:
            logger.debug("Event loop received cancellation.")
        except Exception as e:
            logger.error(f"Error running event loop in thread: {e}")
            logger.error(traceback.format_exc())
            print(f"Error: Event loop in ClientPool thread encountered an issue: {e}", file=sys.stderr)
        finally:
            logger.debug("Closing the event loop.")
            self.loop.close()

    def wait_for_connection(self):
        """
        Waits until the ClientPool is connected to all relays.
        """
        try:
            while not self.client_pool.connected:
                time.sleep(0.1)
        except Exception as e:
            logger.error(f"Error while waiting for ClientPool to connect: {e}")
            logger.error(traceback.format_exc())

    async def publish_event_async(self, event: Event):
        """
        Publishes a signed event to all connected relays using ClientPool.

        :param event: The signed Event object to publish.
        """
        try:
            logger.debug(f"Publishing event: {event.serialize()}")
            self.client_pool.publish(event)
            logger.info(f"Event published with ID: {event.id}")
        except Exception as e:
            logger.error(f"Failed to publish event: {e}")
            logger.error(traceback.format_exc())

    def publish_event(self, event: Event):
        """
        Synchronous wrapper for publishing an event.

        :param event: The signed Event object to publish.
        """
        try:
            asyncio.run_coroutine_threadsafe(self.publish_event_async(event), self.loop)
        except Exception as e:
            logger.error(f"Error in publish_event: {e}")
            print(f"Error: Failed to publish event: {e}", file=sys.stderr)

    async def subscribe_async(self, filters: List[dict], handler: Callable[[ClientPool, str, Event], None]):
        """
        Subscribes to events based on the provided filters using ClientPool.

        :param filters: A list of filter dictionaries.
        :param handler: A callback function to handle incoming events.
        """
        try:
            sub_id = str(uuid.uuid4())
            self.client_pool.subscribe(handlers=handler, filters=filters, sub_id=sub_id)
            logger.info(f"Subscribed to events with subscription ID: {sub_id}")
            self.subscriptions[sub_id] = True
        except Exception as e:
            logger.error(f"Failed to subscribe: {e}")
            logger.error(traceback.format_exc())
            print(f"Error: Failed to subscribe: {e}", file=sys.stderr)

    def subscribe(self, filters: List[dict], handler: Callable[[ClientPool, str, Event], None]):
        """
        Synchronous wrapper for subscribing to events.

        :param filters: A list of filter dictionaries.
        :param handler: A callback function to handle incoming events.
        """
        try:
            asyncio.run_coroutine_threadsafe(self.subscribe_async(filters, handler), self.loop)
        except Exception as e:
            logger.error(f"Error in subscribe: {e}")
            print(f"Error: Failed to subscribe: {e}", file=sys.stderr)

    async def retrieve_json_from_nostr_async(self) -> Optional[bytes]:
        """
        Retrieves the latest encrypted JSON event from Nostr.

        :return: The encrypted JSON data as bytes, or None if retrieval fails.
        """
        try:
            filters = [{
                'authors': [self.key_manager.keys.public_key_hex()],
                'kinds': [Event.KIND_TEXT_NOTE, Event.KIND_ENCRYPT],
                'limit': 1
            }]

            events = []

            def my_handler(the_client, sub_id, evt: Event):
                logger.debug(f"Received event: {evt.serialize()}")
                events.append(evt)

            await self.subscribe_async(filters=filters, handler=my_handler)

            await asyncio.sleep(2)  # Adjust the sleep time as needed

            for sub_id in list(self.subscriptions.keys()):
                self.client_pool.unsubscribe(sub_id)
                del self.subscriptions[sub_id]
                logger.debug(f"Unsubscribed from sub_id {sub_id}")

            if events:
                event = events[0]
                encrypted_json_b64 = event.content

                if event.kind == Event.KIND_ENCRYPT:
                    nip4_encrypt = NIP4Encrypt(self.key_manager.keys)
                    encrypted_json_b64 = nip4_encrypt.decrypt_message(event.content, event.pub_key)

                encrypted_json = base64.b64decode(encrypted_json_b64.encode('utf-8'))
                logger.debug("Encrypted JSON data retrieved successfully.")
                return encrypted_json
            else:
                logger.warning("No events found matching the filters.")
                print("No events found matching the filters.", file=sys.stderr)
                return None

        except Exception as e:
            logger.error(f"Failed to retrieve JSON from Nostr: {e}")
            logger.error(traceback.format_exc())
            print(f"Error: Failed to retrieve JSON from Nostr: {e}", file=sys.stderr)
            return None

    def retrieve_json_from_nostr(self) -> Optional[bytes]:
        """
        Public method to retrieve encrypted JSON from Nostr.

        :return: The encrypted JSON data as bytes, or None if retrieval fails.
        """
        try:
            future = asyncio.run_coroutine_threadsafe(self.retrieve_json_from_nostr_async(), self.loop)
            return future.result()
        except Exception as e:
            logger.error(f"Error in retrieve_json_from_nostr: {e}")
            logger.error(traceback.format_exc())
            print(f"Error: Failed to retrieve JSON from Nostr: {e}", file=sys.stderr)
            return None

    async def do_post_async(self, text: str):
        """
        Creates and publishes a text note event.

        :param text: The content of the text note.
        """
        try:
            event = Event(
                kind=Event.KIND_TEXT_NOTE,
                content=text,
                pub_key=self.key_manager.keys.public_key_hex()
            )
            event.created_at = int(time.time())
            event.sign(self.key_manager.keys.private_key_hex())

            logger.debug(f"Event data: {event.serialize()}")

            await self.publish_event_async(event)

        except Exception as e:
            logger.error(f"An error occurred during publishing: {e}", exc_info=True)
            print(f"Error: An error occurred during publishing: {e}", file=sys.stderr)

    async def subscribe_feed_async(self, handler: Callable[[ClientPool, str, Event], None]):
        """
        Subscribes to the feed of the client's own pubkey.

        :param handler: A callback function to handle incoming events.
        """
        try:
            filters = [{
                'authors': [self.key_manager.keys.public_key_hex()],
                'kinds': [Event.KIND_TEXT_NOTE, Event.KIND_ENCRYPT],
                'limit': 100
            }]

            await self.subscribe_async(filters=filters, handler=handler)
            logger.info("Subscribed to your feed.")

            while True:
                await asyncio.sleep(1)

        except Exception as e:
            logger.error(f"An error occurred during subscription: {e}", exc_info=True)
            print(f"Error: An error occurred during subscription: {e}", file=sys.stderr)

    async def publish_and_subscribe_async(self, text: str):
        """
        Publishes a text note and subscribes to the feed concurrently.

        :param text: The content of the text note to publish.
        """
        try:
            await asyncio.gather(
                self.do_post_async(text),
                self.subscribe_feed_async(self.event_handler.handle_new_event)
            )
        except Exception as e:
            logger.error(f"An error occurred in publish_and_subscribe_async: {e}", exc_info=True)
            print(f"Error: An error occurred in publish and subscribe: {e}", file=sys.stderr)

    def publish_and_subscribe(self, text: str):
        """
        Public method to publish a text note and subscribe to the feed.

        :param text: The content of the text note to publish.
        """
        try:
            asyncio.run_coroutine_threadsafe(self.publish_and_subscribe_async(text), self.loop)
        except Exception as e:
            logger.error(f"Error in publish_and_subscribe: {e}", exc_info=True)
            print(f"Error: Failed to publish and subscribe: {e}", file=sys.stderr)

    def decrypt_and_save_index_from_nostr(self, encrypted_data: bytes) -> None:
        """
        Decrypts the encrypted data retrieved from Nostr and updates the local index file.

        :param encrypted_data: The encrypted data retrieved from Nostr.
        """
        try:
            decrypted_data = self.encryption_manager.decrypt_data(encrypted_data)
            data = json.loads(decrypted_data.decode('utf-8'))
            self.save_json_data(data)
            self.update_checksum()
            logger.info("Index file updated from Nostr successfully.")
            print("Index file updated from Nostr successfully.", file=sys.stdout)
        except Exception as e:
            logger.error(f"Failed to decrypt and save data from Nostr: {e}")
            logger.error(traceback.format_exc())
            print(f"Error: Failed to decrypt and save data from Nostr: {e}", file=sys.stderr)

    def save_json_data(self, data: dict) -> None:
        """
        Saves the JSON data to the index file in an encrypted format.

        :param data: The JSON data to save.
        """
        try:
            encrypted_data = self.encryption_manager.encrypt_data(data)
            with lock_file(INDEX_FILE, fcntl.LOCK_EX):
                with open(INDEX_FILE, 'wb') as f:
                    f.write(encrypted_data)
            logger.debug(f"Encrypted data saved to {INDEX_FILE}.")
            print(f"Encrypted data saved to {INDEX_FILE}.", file=sys.stdout)
        except Exception as e:
            logger.error(f"Failed to save encrypted data: {e}")
            logger.error(traceback.format_exc())
            print(f"Error: Failed to save encrypted data: {e}", file=sys.stderr)
            raise

    def update_checksum(self) -> None:
        """
        Updates the checksum file for the password database.
        """
        try:
            decrypted_data = self.decrypt_data_from_file(INDEX_FILE)
            content = decrypted_data.decode('utf-8')
            logger.debug("Calculating checksum of the updated file content.")

            checksum = hashlib.sha256(content.encode('utf-8')).hexdigest()
            logger.debug(f"New checksum: {checksum}")

            with open(DATA_CHECKSUM_FILE, 'w') as f:
                f.write(checksum)
            logger.debug(f"Updated data checksum written to '{DATA_CHECKSUM_FILE}'.")
            print("[+] Checksum updated successfully.", file=sys.stdout)

        except Exception as e:
            logger.error(f"Failed to update checksum: {e}")
            logger.error(traceback.format_exc())
            print(f"Error: Failed to update checksum: {e}", file=sys.stderr)

    def decrypt_data_from_file(self, file_path: str) -> bytes:
        """
        Decrypts data directly from a file.

        :param file_path: Path to the encrypted file.
        :return: Decrypted data as bytes.
        """
        try:
            with lock_file(file_path, fcntl.LOCK_SH):
                with open(file_path, 'rb') as f:
                    encrypted_data = f.read()
            decrypted_data = self.encryption_manager.decrypt_data(encrypted_data)
            logger.debug(f"Data decrypted from file '{file_path}'.")
            return decrypted_data
        except Exception as e:
            logger.error(f"Failed to decrypt data from file '{file_path}': {e}")
            logger.error(traceback.format_exc())
            print(f"Error: Failed to decrypt data from file '{file_path}': {e}", file=sys.stderr)
            raise

    def publish_json_to_nostr(self, encrypted_json: bytes, to_pubkey: str = None):
        """
        Public method to post encrypted JSON to Nostr.

        :param encrypted_json: The encrypted JSON data to be sent.
        :param to_pubkey: (Optional) The recipient's public key for encryption.
        """
        try:
            encrypted_json_b64 = base64.b64encode(encrypted_json).decode('utf-8')
            logger.debug(f"Encrypted JSON (base64): {encrypted_json_b64}")

            event = Event(kind=Event.KIND_TEXT_NOTE, content=encrypted_json_b64, pub_key=self.key_manager.keys.public_key_hex())

            event.created_at = int(time.time())

            if to_pubkey:
                nip4_encrypt = NIP4Encrypt(self.key_manager.keys)
                event.content = nip4_encrypt.encrypt_message(event.content, to_pubkey)
                event.kind = Event.KIND_ENCRYPT
                logger.debug(f"Encrypted event content: {event.content}")

            event.sign(self.key_manager.keys.private_key_hex())
            logger.debug("Event created and signed")

            self.publish_event(event)
            logger.debug("Event published")

        except Exception as e:
            logger.error(f"Failed to publish JSON to Nostr: {e}")
            logger.error(traceback.format_exc())
            print(f"Error: Failed to publish JSON to Nostr: {e}", file=sys.stderr)

    def retrieve_json_from_nostr_sync(self) -> Optional[bytes]:
        """
        Public method to retrieve encrypted JSON from Nostr.

        :return: The encrypted JSON data as bytes, or None if retrieval fails.
        """
        try:
            return self.retrieve_json_from_nostr()
        except Exception as e:
            logger.error(f"Error in retrieve_json_from_nostr_sync: {e}")
            logger.error(traceback.format_exc())
            print(f"Error: Failed to retrieve JSON from Nostr: {e}", file=sys.stderr)
            return None

    def decrypt_and_save_index_from_nostr_public(self, encrypted_data: bytes) -> None:
        """
        Public method to decrypt and save data from Nostr.

        :param encrypted_data: The encrypted data retrieved from Nostr.
        """
        try:
            self.decrypt_and_save_index_from_nostr(encrypted_data)
        except Exception as e:
            logger.error(f"Failed to decrypt and save index from Nostr: {e}")
            print(f"Error: Failed to decrypt and save index from Nostr: {e}", file=sys.stderr)

    async def close_client_pool_async(self):
        """
        Closes the ClientPool gracefully by canceling all pending tasks and stopping the event loop.
        """
        if self.is_shutting_down:
            logger.debug("Shutdown already in progress.")
            return

        try:
            self.is_shutting_down = True
            logger.debug("Initiating ClientPool shutdown.")

            # Set the shutdown event
            self._shutdown_event.set()

            # Cancel all subscriptions
            for sub_id in list(self.subscriptions.keys()):
                try:
                    self.client_pool.unsubscribe(sub_id)
                    del self.subscriptions[sub_id]
                    logger.debug(f"Unsubscribed from sub_id {sub_id}")
                except Exception as e:
                    logger.warning(f"Error unsubscribing from {sub_id}: {e}")

            # Close all WebSocket connections
            if hasattr(self.client_pool, 'clients'):
                for client in self.client_pool.clients:
                    try:
                        await client.close()
                        logger.debug(f"Closed connection to relay: {client.url}")
                    except Exception as e:
                        logger.warning(f"Error closing connection to {client.url}: {e}")

            # Gather and cancel all tasks
            current_task = asyncio.current_task()
            tasks = [task for task in asyncio.all_tasks(loop=self.loop)
                     if task != current_task and not task.done()]

            if tasks:
                logger.debug(f"Cancelling {len(tasks)} pending tasks.")
                for task in tasks:
                    task.cancel()

                # Wait for all tasks to be cancelled with a timeout
                try:
                    await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), timeout=5)
                except asyncio.TimeoutError:
                    logger.warning("Timeout waiting for tasks to cancel")

            logger.debug("Stopping the event loop.")
            self.loop.stop()
            logger.info("Event loop stopped successfully.")

        except Exception as e:
            logger.error(f"Error during async shutdown: {e}")
            logger.error(traceback.format_exc())
        finally:
            self.is_shutting_down = False

    def close_client_pool(self):
        """
        Public method to close the ClientPool gracefully.
        """
        if self.is_shutting_down:
            logger.debug("Shutdown already in progress. Skipping redundant shutdown.")
            return

        try:
            # Schedule the coroutine to close the client pool
            future = asyncio.run_coroutine_threadsafe(self.close_client_pool_async(), self.loop)
            
            # Wait for the coroutine to finish with a shorter timeout
            try:
                future.result(timeout=10)
            except concurrent.futures.TimeoutError:
                logger.warning("Initial shutdown attempt timed out, forcing cleanup...")
            
            # Additional cleanup regardless of timeout
            try:
                self.loop.stop()
                # Give a short grace period for the loop to stop
                time.sleep(0.5)
                
                if self.loop.is_running():
                    logger.warning("Loop still running after stop, closing forcefully")
                    self.loop.close()
                
                # Wait for the thread with a reasonable timeout
                if self.loop_thread.is_alive():
                    self.loop_thread.join(timeout=5)
                    
                if self.loop_thread.is_alive():
                    logger.warning("Thread still alive after join, may need to be force-killed")
                
            except Exception as cleanup_error:
                logger.error(f"Error during final cleanup: {cleanup_error}")
            
            logger.info("ClientPool shutdown complete")
            
        except Exception as e:
            logger.error(f"Error in close_client_pool: {e}")
            logger.error(traceback.format_exc())
        finally:
            self.is_shutting_down = False
