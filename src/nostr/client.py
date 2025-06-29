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
from pathlib import Path

from monstr.client.client import ClientPool
from monstr.encrypt import Keys, NIP4Encrypt
from monstr.event.event import Event

import threading
import uuid

from .key_manager import KeyManager
from .encryption_manager import EncryptionManager
from .event_handler import EventHandler
from constants import APP_DIR
from utils.file_lock import exclusive_lock

# Get the logger for this module
logger = logging.getLogger(__name__)

# Set the logging level to WARNING or ERROR to suppress debug logs
logger.setLevel(logging.WARNING)

DEFAULT_RELAYS = [
    "wss://relay.snort.social",
    "wss://nostr.oxtr.dev",
    "wss://relay.primal.net",
]

# nostr/client.py

# src/nostr/client.py


class NostrClient:
    """
    NostrClient Class

    Handles interactions with the Nostr network, including publishing and retrieving encrypted events.
    Utilizes deterministic key derivation via BIP-85 and integrates with the monstr library for protocol operations.
    """

    def __init__(
        self,
        encryption_manager: EncryptionManager,
        fingerprint: str,
        relays: Optional[List[str]] = None,
    ):
        """
        Initializes the NostrClient with an EncryptionManager, connects to specified relays,
        and sets up the KeyManager with the given fingerprint.

        :param encryption_manager: An instance of EncryptionManager for handling encryption/decryption.
        :param fingerprint: The fingerprint to differentiate key derivations for unique identities.
        :param relays: (Optional) A list of relay URLs to connect to. Defaults to predefined relays.
        """
        try:
            # Assign the encryption manager and fingerprint
            self.encryption_manager = encryption_manager
            self.fingerprint = fingerprint  # Track the fingerprint
            self.fingerprint_dir = (
                self.encryption_manager.fingerprint_dir
            )  # If needed to manage directories

            # Initialize KeyManager with the decrypted parent seed and the provided fingerprint
            self.key_manager = KeyManager(
                self.encryption_manager.decrypt_parent_seed(), self.fingerprint
            )

            # Initialize event handler and client pool
            self.event_handler = EventHandler()
            self.relays = relays if relays else DEFAULT_RELAYS
            self.client_pool = ClientPool(self.relays)
            self.subscriptions = {}

            # Initialize client pool and mark NostrClient as running
            self.initialize_client_pool()
            logger.info("NostrClient initialized successfully.")

            # For shutdown handling
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
            print(
                f"Error: Event loop in ClientPool thread encountered an issue: {e}",
                file=sys.stderr,
            )
        finally:
            if not self.loop.is_closed():
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
            logger.debug(f"Finished publishing event: {event.id}")
        except Exception as e:
            logger.error(f"Failed to publish event: {e}")
            logger.error(traceback.format_exc())

    def publish_event(self, event: Event):
        """
        Synchronous wrapper for publishing an event.

        :param event: The signed Event object to publish.
        """
        try:
            logger.debug(f"Submitting publish_event_async for event ID: {event.id}")
            future = asyncio.run_coroutine_threadsafe(
                self.publish_event_async(event), self.loop
            )
            # Wait for the future to complete
            future.result(timeout=5)  # Adjust the timeout as needed
        except Exception as e:
            logger.error(f"Error in publish_event: {e}")
            print(f"Error: Failed to publish event: {e}", file=sys.stderr)

    async def subscribe_async(
        self, filters: List[dict], handler: Callable[[ClientPool, str, Event], None]
    ):
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

    def subscribe(
        self, filters: List[dict], handler: Callable[[ClientPool, str, Event], None]
    ):
        """
        Synchronous wrapper for subscribing to events.

        :param filters: A list of filter dictionaries.
        :param handler: A callback function to handle incoming events.
        """
        try:
            asyncio.run_coroutine_threadsafe(
                self.subscribe_async(filters, handler), self.loop
            )
        except Exception as e:
            logger.error(f"Error in subscribe: {e}")
            print(f"Error: Failed to subscribe: {e}", file=sys.stderr)

    async def retrieve_json_from_nostr_async(self) -> Optional[str]:
        """
        Retrieves the latest encrypted JSON event from Nostr.

        :return: The encrypted JSON data as a Base64-encoded string, or None if retrieval fails.
        """
        try:
            filters = [
                {
                    "authors": [self.key_manager.keys.public_key_hex()],
                    "kinds": [Event.KIND_TEXT_NOTE, Event.KIND_ENCRYPT],
                    "limit": 1,
                }
            ]

            events = []

            def my_handler(the_client, sub_id, evt: Event):
                logger.debug(f"Received event: {evt.serialize()}")
                events.append(evt)

            await self.subscribe_async(filters=filters, handler=my_handler)

            await asyncio.sleep(2)  # Adjust the sleep time as needed

            # Unsubscribe from all subscriptions
            for sub_id in list(self.subscriptions.keys()):
                self.client_pool.unsubscribe(sub_id)
                del self.subscriptions[sub_id]
                logger.debug(f"Unsubscribed from sub_id {sub_id}")

            if events:
                event = events[0]
                content_base64 = event.content

                if event.kind == Event.KIND_ENCRYPT:
                    nip4_encrypt = NIP4Encrypt(self.key_manager.keys)
                    content_base64 = nip4_encrypt.decrypt_message(
                        event.content, event.pub_key
                    )

                # Return the Base64-encoded content as a string
                logger.debug("Encrypted JSON data retrieved successfully.")
                return content_base64
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
            future = asyncio.run_coroutine_threadsafe(
                self.retrieve_json_from_nostr_async(), self.loop
            )
            return future.result(timeout=10)
        except concurrent.futures.TimeoutError:
            logger.error("Timeout occurred while retrieving JSON from Nostr.")
            print(
                "Error: Timeout occurred while retrieving JSON from Nostr.",
                file=sys.stderr,
            )
            return None
        except Exception as e:
            logger.error(f"Error in retrieve_json_from_nostr: {e}")
            logger.error(traceback.format_exc())
            print(f"Error: Failed to retrieve JSON from Nostr: {e}", "red")
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
                pub_key=self.key_manager.keys.public_key_hex(),
            )
            event.created_at = int(time.time())
            event.sign(self.key_manager.keys.private_key_hex())

            logger.debug(f"Event data: {event.serialize()}")

            await self.publish_event_async(event)
            logger.debug("Finished do_post_async")
        except Exception as e:
            logger.error(f"An error occurred during publishing: {e}", exc_info=True)
            print(f"Error: An error occurred during publishing: {e}", file=sys.stderr)

    async def subscribe_feed_async(
        self, handler: Callable[[ClientPool, str, Event], None]
    ):
        """
        Subscribes to the feed of the client's own pubkey.

        :param handler: A callback function to handle incoming events.
        """
        try:
            filters = [
                {
                    "authors": [self.key_manager.keys.public_key_hex()],
                    "kinds": [Event.KIND_TEXT_NOTE, Event.KIND_ENCRYPT],
                    "limit": 100,
                }
            ]

            await self.subscribe_async(filters=filters, handler=handler)
            logger.info("Subscribed to your feed.")

            # Removed the infinite loop to prevent blocking

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
                self.subscribe_feed_async(self.event_handler.handle_new_event),
            )
        except Exception as e:
            logger.error(
                f"An error occurred in publish_and_subscribe_async: {e}", exc_info=True
            )
            print(
                f"Error: An error occurred in publish and subscribe: {e}",
                file=sys.stderr,
            )

    def publish_and_subscribe(self, text: str):
        """
        Public method to publish a text note and subscribe to the feed.

        :param text: The content of the text note to publish.
        """
        try:
            asyncio.run_coroutine_threadsafe(
                self.publish_and_subscribe_async(text), self.loop
            )
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
            data = json.loads(decrypted_data.decode("utf-8"))
            self.save_json_data(data)
            self.update_checksum()
            logger.info("Index file updated from Nostr successfully.")
            print(colored("Index file updated from Nostr successfully.", "green"))
        except Exception as e:
            logger.error(f"Failed to decrypt and save data from Nostr: {e}")
            logger.error(traceback.format_exc())
            print(
                colored(
                    f"Error: Failed to decrypt and save data from Nostr: {e}", "red"
                )
            )

    def save_json_data(self, data: dict) -> None:
        """
        Saves the JSON data to the index file in an encrypted format.

        :param data: The JSON data to save.
        """
        try:
            encrypted_data = self.encryption_manager.encrypt_data(
                json.dumps(data).encode("utf-8")
            )
            index_file_path = self.fingerprint_dir / "seedpass_passwords_db.json.enc"
            with exclusive_lock(index_file_path):
                with open(index_file_path, "wb") as f:
                    f.write(encrypted_data)
            logger.debug(f"Encrypted data saved to {index_file_path}.")
            print(colored(f"Encrypted data saved to '{index_file_path}'.", "green"))
        except Exception as e:
            logger.error(f"Failed to save encrypted data: {e}")
            logger.error(traceback.format_exc())
            print(colored(f"Error: Failed to save encrypted data: {e}", "red"))
            raise

    def update_checksum(self) -> None:
        """
        Updates the checksum file for the password database.
        """
        try:
            index_file_path = self.fingerprint_dir / "seedpass_passwords_db.json.enc"
            decrypted_data = self.decrypt_data_from_file(index_file_path)
            content = decrypted_data.decode("utf-8")
            logger.debug("Calculating checksum of the updated file content.")

            checksum = hashlib.sha256(content.encode("utf-8")).hexdigest()
            logger.debug(f"New checksum: {checksum}")

            checksum_file = self.fingerprint_dir / "seedpass_passwords_db_checksum.txt"

            with exclusive_lock(checksum_file):
                with open(checksum_file, "w") as f:
                    f.write(checksum)

            os.chmod(checksum_file, 0o600)

            logger.debug(
                f"Checksum for '{index_file_path}' updated and written to '{checksum_file}'."
            )
            print(colored(f"Checksum for '{index_file_path}' updated.", "green"))
        except Exception as e:
            logger.error(f"Failed to update checksum: {e}")
            logger.error(traceback.format_exc())
            print(colored(f"Error: Failed to update checksum: {e}", "red"))

    def decrypt_data_from_file(self, file_path: Path) -> bytes:
        """
        Decrypts data directly from a file.

        :param file_path: Path to the encrypted file as a Path object.
        :return: Decrypted data as bytes.
        """
        try:
            with exclusive_lock(file_path):
                with open(file_path, "rb") as f:
                    encrypted_data = f.read()
            decrypted_data = self.encryption_manager.decrypt_data(encrypted_data)
            logger.debug(f"Data decrypted from file '{file_path}'.")
            return decrypted_data
        except Exception as e:
            logger.error(f"Failed to decrypt data from file '{file_path}': {e}")
            logger.error(traceback.format_exc())
            print(
                colored(
                    f"Error: Failed to decrypt data from file '{file_path}': {e}", "red"
                )
            )
            raise

    def publish_json_to_nostr(self, encrypted_json: bytes, to_pubkey: str = None):
        """
        Public method to post encrypted JSON to Nostr.

        :param encrypted_json: The encrypted JSON data to be sent.
        :param to_pubkey: (Optional) The recipient's public key for encryption.
        """
        try:
            encrypted_json_b64 = base64.b64encode(encrypted_json).decode("utf-8")
            logger.debug(f"Encrypted JSON (base64): {encrypted_json_b64}")

            event = Event(
                kind=Event.KIND_TEXT_NOTE,
                content=encrypted_json_b64,
                pub_key=self.key_manager.keys.public_key_hex(),
            )

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
        Retrieves encrypted data from Nostr and Base64-decodes it.

        Returns:
            Optional[bytes]: The encrypted data as bytes if successful, None otherwise.
        """
        try:
            future = asyncio.run_coroutine_threadsafe(
                self.retrieve_json_from_nostr_async(), self.loop
            )
            content_base64 = future.result(timeout=10)

            if not content_base64:
                logger.debug("No data retrieved from Nostr.")
                return None

            # Base64-decode the content
            encrypted_data = base64.urlsafe_b64decode(content_base64.encode("utf-8"))
            logger.debug(
                "Encrypted data retrieved and Base64-decoded successfully from Nostr."
            )
            return encrypted_data
        except concurrent.futures.TimeoutError:
            logger.error("Timeout occurred while retrieving JSON from Nostr.")
            print(
                "Error: Timeout occurred while retrieving JSON from Nostr.",
                file=sys.stderr,
            )
            return None
        except Exception as e:
            logger.error(f"Error in retrieve_json_from_nostr: {e}")
            logger.error(traceback.format_exc())
            print(f"Error: Failed to retrieve JSON from Nostr: {e}", "red")
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
            print(f"Error: Failed to decrypt and save index from Nostr: {e}", "red")

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
            if hasattr(self.client_pool, "clients"):
                tasks = [
                    self.safe_close_connection(client)
                    for client in self.client_pool.clients
                ]
                await asyncio.gather(*tasks, return_exceptions=True)

            # Gather and cancel all tasks
            current_task = asyncio.current_task()
            tasks = [
                task
                for task in asyncio.all_tasks(loop=self.loop)
                if task != current_task and not task.done()
            ]

            if tasks:
                logger.debug(f"Cancelling {len(tasks)} pending tasks.")
                for task in tasks:
                    task.cancel()

                # Wait for all tasks to be cancelled with a timeout
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=True), timeout=5
                    )
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
            future = asyncio.run_coroutine_threadsafe(
                self.close_client_pool_async(), self.loop
            )

            # Wait for the coroutine to finish with a timeout
            try:
                future.result(timeout=10)
            except concurrent.futures.TimeoutError:
                logger.warning("Initial shutdown attempt timed out, forcing cleanup...")

            # Additional cleanup regardless of timeout
            try:
                self.loop.call_soon_threadsafe(self.loop.stop)
                # Give a short grace period for the loop to stop
                time.sleep(0.5)

                if self.loop.is_running():
                    logger.warning("Loop still running after stop, closing forcefully")
                    self.loop.call_soon_threadsafe(self.loop.close)

                # Wait for the thread with a reasonable timeout
                if self.loop_thread.is_alive():
                    self.loop_thread.join(timeout=5)

                if self.loop_thread.is_alive():
                    logger.warning(
                        "Thread still alive after join, may need to be force-killed"
                    )

            except Exception as cleanup_error:
                logger.error(f"Error during final cleanup: {cleanup_error}")

            logger.info("ClientPool shutdown complete")

        except Exception as e:
            logger.error(f"Error in close_client_pool: {e}")
            logger.error(traceback.format_exc())
        finally:
            self.is_shutting_down = False

    async def safe_close_connection(self, client):
        try:
            await client.close_connection()
            logger.debug(f"Closed connection to relay: {client.url}")
        except AttributeError:
            logger.warning(
                f"Client object has no attribute 'close_connection'. Skipping closure for {client.url}."
            )
        except Exception as e:
            logger.warning(f"Error closing connection to {client.url}: {e}")
