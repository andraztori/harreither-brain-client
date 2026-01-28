import copy
import json
import logging
from typing import Any, Tuple

from .message import MessageSend, MC_AUTO
from .type_int import TypeInt

logger = logging.getLogger(__name__)


class Entry(dict):
    """A dict-like entry with built-in normalization."""

    def normalize(self) -> Any:
        """Deep-copy self while removing 'name', 'highlight', and '_screen_key' fields for comparisons."""
        return self._normalize_value(dict(self))

    @staticmethod
    def _normalize_value(value: Any) -> Any:
        """Helper method to normalize a dict-representation of an entry recursively."""
        if isinstance(value, dict):
            # Remove name, highlight, and _screen_key fields if present
            value = copy.deepcopy(value)
            value.pop("name", None)  # we should not be doing that
            value.pop("highlight", None)
            value.pop("_screen_key", None)
            # Recursively normalize nested values
            for k, v in value.items():
                value[k] = Entry._normalize_value(v)
            return value
        if isinstance(value, list):
            return [Entry._normalize_value(v) for v in value]
        return value

    def message_edit_value(self, value: int) -> MessageSend:
        """Create a SELECT message to change the device value.

        Args:
            value: The index of the selected option (0-based).

        Returns:
            A MessageSend object for the ACTION_EDITED_VALUE message.
        """
        vid = self["VID"]
        detail = self["detail"]
        objid = self.get("objID")

        payload: dict[str, Any] = {
            "VID": vid,
            "detail": detail,
            "value": value,
            "validity": 0,
        }
        if objid is not None:
            payload["objID"] = objid

        return MessageSend(
            type_int=TypeInt.ACTION_EDITED_VALUE,
            mc=MC_AUTO,
            payload=payload,
        )

    def message_activate_entering_screen(self) -> MessageSend:
        """Create a message to activate the screen associated with this entry.

        Returns:
            A MessageSend object for the ACTUAL_SCREEN message.
        """
        originating_screen_key = self.get("_screen_key")
        if not originating_screen_key:
            raise ValueError(f"Entry {self} has no _screen_key")

        screen_id, screen_obj_id = originating_screen_key
        screen_payload: dict[str, Any] = {"screenID": screen_id}
        if screen_obj_id is not None:
            screen_payload["objID"] = screen_obj_id

        return MessageSend(
            type_int=TypeInt.ACTUAL_SCREEN,
            mc=MC_AUTO,
            payload=screen_payload,
        )

    def message_action_selected(self) -> MessageSend:
        """Create a message to trigger ACTION_SELECTED for this entry.
            You need to activate the screen before that for this to work properly!

        Returns:
            A MessageSend object for the ACTION_SELECTED message.
        """
        vid = self["VID"]
        detail = self["detail"]
        objid = self.get("objID")

        payload: dict[str, Any] = {"VID": vid, "detail": detail}
        if objid is not None:
            payload["objID"] = objid

        return MessageSend(
            type_int=TypeInt.ACTION_SELECTED,
            mc=MC_AUTO,
            payload=payload,
        )


class Entries:
    def __init__(self, connection):
        self._entries = {}
        self.connection = connection
        self.dbentries = {}
        self.screens = {}
        self.alerts = []

    def make_key_from_object(self, object) -> Tuple[Any, Any, Any]:
        return (object.get("VID"), object["detail"], object.get("objID", None))

    def get_entry(self, key: Tuple[Any, Any, Any]) -> Entry | None:
        return self._entries.get(key)

    async def create_entry(self, key, entry_data):
        # if key[1] == 0:
        #    return
        new = True

        # Create Entry object from input data
        entry = Entry(entry_data)

        if key in self._entries:
            _vid_obj = entry.get("_vid_obj", {})

            # Only enforce duplicate checks in strict mode
            if self.connection.strict and _vid_obj.get("type") not in (23, 4):
                existing_norm = self._entries[key].normalize()
                incoming_norm = entry.normalize()

                if existing_norm != incoming_norm:
                    raise ValueError(
                        f"create_entry() Entry {key} already exists, current data: {dict(self._entries[key])}, new data: {entry_data}"
                    )
                logger.debug(
                    "create_entry() Entry %s already exists with identical content (ignoring some fields), overwriting",
                    key,
                )
                new = False
        self._entries[key] = entry
        await self.connection.async_notify_update(key, entry, new)

    async def update_entry(self, key, updated_entry):
        if key == (0, 0, None):
            return
        if key == (318, 1, None):
            logger.info(f"update_entry(): Got a update of an entry that does not exist, likely 318 is an error message: {key}, entry: {updated_entry}")
            return
        entry = self.get_entry(key)
        if entry is None:
            raise ValueError(f"update_entry() Entry {key} does not exist")

        vid = key[0]
        vid_info = self.dbentries[vid]
        vid_text = vid_info["text"]
        vid_text = vid_info.get("text", f"VID:{vid}")
        entry_name = entry.get("name", "")

        for k, v in updated_entry.items():
            old_value = entry.get(k)
            if old_value != v:
                old_value_repr = repr(old_value)
                v_repr = repr(v)
                logger.debug(
                    f"Entry {vid_text} {entry_name} ({key}) field '{k}': {old_value_repr} -> {v_repr}"
                )
                entry[k] = v

        await self.connection.async_notify_update(key, entry, False)

    def save_entries(self):
        dumpable = {str(k): dict(v) for k, v in self._entries.items()}
        if self.connection.dump_entities:
            with open("entries.json", "w", encoding="utf-8") as f:
                json.dump(dumpable, f, indent=4, ensure_ascii=False)

    def save_screens(self):
        """Save screens dict with tuple keys to JSON, converting keys to strings and removing _screen_key."""
        if self.connection.dump_entities:
            # Helper to recursively remove _screen_key from items
            def remove_screen_key(obj):
                if isinstance(obj, dict):
                    result = {
                        k: remove_screen_key(v)
                        for k, v in obj.items()
                        if k != "_screen_key"
                    }
                    return result
                elif isinstance(obj, list):
                    return [remove_screen_key(item) for item in obj]
                return obj

            # Clean screens data
            cleaned_screens = remove_screen_key(self.screens)
            dumpable = {str(k): v for k, v in cleaned_screens.items()}
            with open("screens.json", "w", encoding="utf-8") as f:
                json.dump(dumpable, f, indent=4, ensure_ascii=False)
