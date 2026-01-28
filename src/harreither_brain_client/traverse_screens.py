import asyncio
import logging

from .connection import Connection
from .entries import Entry


class TraverseScreens:
    """Traverses all screens. Act as a very disciplined human going through all the menues.
    The issue is that some screens we get to know about ahead of time (sent by the device at
    initialization of the connection), but for others we actually need to enter them to get
    their descriptions

    The logics is that if it's not a back button, and it's not an action that does something,
    we should try clicking and seeing what happens.

    Hopefully we have the right conditions for those:
    detail: 0 => back button
    detail: 1 => action that changes something -- but we don't know what as this is business logic
    on the device's side.
    All other "buttons" presumably lead to screens.
    """

    def __init__(self, conn_obj: Connection) -> None:
        self.conn_obj = conn_obj
        self.explore_queue: asyncio.Queue = asyncio.Queue()
        self.requested_screens: set = set()

    async def entry_update_callback(self, key: tuple, entry: Entry, new: bool) -> None:
        """Process updates as they arrive from the server."""
        # vid 317 is system time
        # vid 318 is "a problem"
        if key == (0, 0, None) or key == (317, 1, None) or key == (318, 1, None):
            return
        update_type = "NEW" if new else "UPDATE"
        # print(f"[{update_type}] {key}: {entry}")

        # Log entities with detail = 0 or detail = 1 to a separate file
        detail = key[1]
        _vid_obj = entry.get("_vid_obj", {})
        # if new and detail in (0, 1) and _vid_obj.get("type") == 1:
        #    with open("detail_0_1_entities.txt", "a", encoding="utf-8") as f:
        #        f.write(f"{update_type}: {key}: {entry}\n")

        # Check if this is a type 1 entry and add to explore queue (but exclude detail=1)
        if new and detail not in (0, 1):
            if _vid_obj.get("type") == 1:
                await self.explore_queue.put((key, entry))
                logging.debug(f"Added entry to explore queue: {key}")

    async def traverse_screens(self) -> None:
        """Traverse screens by requesting details for type 1 entries from the explore queue."""
        logging.info("Waiting for connection initialization to complete...")
        await self.conn_obj.event_initial_setup_complete.wait()
        logging.info(
            "Initialization complete. Traversing all the screens to do discovery."
        )

        # Continuously pull items from the explore queue
        while True:
            try:
                key, entry = await asyncio.wait_for(
                    self.explore_queue.get(), timeout=3.0
                )
            except asyncio.TimeoutError:
                logging.info("traverse_screens(): queue idle; exiting traversal")
                break

            try:
                vid, detail, obj_id = key  # unpack tuple
                originating_screen_key = entry.get("_screen_key")
                if not originating_screen_key:
                    logging.error(
                        f"No originating_screen_key found for entry {key}, skipping"
                    )
                    continue

                # Create ACTUAL_SCREEN message to navigate to the originating screen
                screen_msg = entry.message_activate_entering_screen()
                actual_screen_ack = await self.conn_obj.enqueue_message_get_ack(
                    screen_msg
                )
                # logging.info(
                #    f"Received ACK for ACTUAL_SCREEN {originating_screen_key},  succes: {actual_screen_ack}"
                # )
                # Create and enqueue the ACTION_SELECTED message
                msg = entry.message_action_selected()
                # POTENTIAL BUG : these actions can trigger additional entry_update_callback calls as the device responds.
                # ASSESMENT: IT'S OK as this is run immediately after connection initialization, before

                logging.debug(f"Enqueued ACTION_SELECTED for {key}: {msg.payload}")
                action_selected_ack = await self.conn_obj.enqueue_message_get_ack(msg)
                logging.debug(
                    f"Received ACK for ACTION_SELECTED {key}, succes: {action_selected_ack}"
                )
            except asyncio.CancelledError:
                logging.info("Traverse_screens() processing CanceledError exception.")
                raise

        logging.info("traverse_screens() complete")
