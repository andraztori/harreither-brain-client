import asyncio
import logging

from .connection import Connection
from .message import MessageSend
from .type_int import TypeInt


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
    
    def __init__(self, conn_obj: Connection):
        self.conn_obj = conn_obj
        self.explore_queue: asyncio.Queue = asyncio.Queue()
        self.requested_screens: set = set()
    
    async def entry_update_callback(self, key: str, value_dict: dict, new: bool) -> None:
        """Process updates as they arrive from the server."""
        # vid 317 is system time
        # vid 318 is "a problem"
        if key == (0, 0, None) or key == (317, 1, None) or key == (318, 1, None):
            return
        update_type = "NEW" if new else "UPDATE"
        #print(f"[{update_type}] {key}: {value_dict}")
        
        # Log entities with detail = 0 or detail = 1 to a separate file
        detail = key[1]
        _vid_obj = value_dict.get("_vid_obj", {})
        if new and detail in (0, 1) and _vid_obj.get("type") == 1:
            with open("detail_0_1_entities.txt", "a", encoding="utf-8") as f:
                f.write(f"{update_type}: {key}: {value_dict}\n")

        # Check if this is a type 1 entry and add to explore queue (but exclude detail=1)
        if new and detail not in (0, 1):
            if _vid_obj.get("type") == 1:
                originating_screen_key = value_dict.get("_screen_key")
                await self.explore_queue.put((key, originating_screen_key))
                logging.debug(f"Added entry to explore queue: {key}")
                with open("detail_explored.txt", "a", encoding="utf-8") as f:
                    f.write(f"{update_type}: {key}: {value_dict}\n")
    
    async def traverse_screens(self) -> None:
        """Traverse screens by requesting details for type 1 entries from the explore queue."""
        logging.info("Waiting for connection initialization to complete...")
        await self.conn_obj.event_initial_setup_complete.wait()
        logging.info("Initialization complete. Traversing all the screens to do discovery.")

        # Continuously pull items from the explore queue
        while True:
            try:
                key, originating_screen_key = await asyncio.wait_for(self.explore_queue.get(), timeout=3.0)
            except asyncio.TimeoutError:
                logging.info("traverse_screens(): queue idle; exiting traversal")
                break
            
            try:
                vid, detail, obj_id = key #unpack tuple
                
                # The screen we're about to enter by clicking this entry
                entering_screen_key = (detail, obj_id)
                
                # we need to check for both - since request can be in-flight
                # Skip if we already requested this screen
                if entering_screen_key in self.requested_screens:
                    logging.debug(f"Already requested screen {entering_screen_key}, skipping")
                    continue
                self.requested_screens.add(entering_screen_key)

                # Skip traversal if we already know this screen
                if entering_screen_key in self.conn_obj.data.screens:
                    logging.debug(f"Screen {entering_screen_key} already known; skipping traversal")
                    continue

                # Build the payload
                payload = {"VID": vid, "detail": detail}
                if obj_id is not None:
                    payload["objID"] = obj_id
                
                if not originating_screen_key:
                    logging.warning(f"No originating_screen_key found for entry {key}, skipping")
                    continue
                
                screen_id, screen_obj_id = originating_screen_key # unpack tuple
                
                # Send ACTUAL_SCREEN first to navigate to the originating screen
                screen_payload = {"screenID": screen_id}
                if screen_obj_id is not None:
                    screen_payload["objID"] = screen_obj_id
                
                screen_msg = MessageSend(
                    type_int=TypeInt.ACTUAL_SCREEN,
                    mc=self.conn_obj.new_message_reference(),
                    payload=screen_payload,
                )
                logging.debug(f"Sending ACTUAL_SCREEN with {screen_payload} prior to ACTION_SELECTED {key}")
                actual_screen_ack = await self.conn_obj.enqueue_message_get_ack(screen_msg)
                logging.debug(f"Received ACK for ACTUAL_SCREEN {screen_payload}, succes: {actual_screen_ack}")
                
                # Create and enqueue the ACTION_SELECTED message
                msg = MessageSend(
                    type_int=TypeInt.ACTION_SELECTED,
                    mc=self.conn_obj.new_message_reference(),
                    payload=payload,
                )
                # POTENTIAL BUG : these actions can trigger additional entry_update_callback calls as the device responds.
                # ASSESMENT: IT'S OK as this is run immediately after connection initialization, before 
                

                logging.debug(f"Enqueued ACTION_SELECTED for {key}: {payload}")
                action_selected_ack = await self.conn_obj.enqueue_message_get_ack(msg)
                logging.debug(f"Received ACK for ACTUAL_SCREEN {key}, succes: {action_selected_ack}")
            except asyncio.CancelledError:
                logging.info("Traverse_screens() processing CanceledError exception.")
                raise
        
        logging.info("traverse_screens() complete")
