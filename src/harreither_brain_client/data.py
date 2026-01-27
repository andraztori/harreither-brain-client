import copy
import json
import logging
from typing import Any, Tuple

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

    def message_select(self, value: int) -> "MessageSend":
        """Create a SELECT message to change the device value.

        Args:
            value: The index of the selected option (0-based).

        Returns:
            A MessageSend object for the ACTION_EDITED_VALUE message.
        """
        from .message import MessageSend
        from .type_int import TypeInt

        vid = self.get("_vid")
        detail = self.get("_detail")
        objid = self.get("_objid")

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
            payload=payload,
        )

    def message_activate_entering_screen(self, connection: Any) -> "MessageSend":
        """Create a message to activate the screen associated with this entry.

        Args:
            connection: The connection object to get message reference from.

        Returns:
            A MessageSend object for the ACTUAL_SCREEN message.
        """
        from .message import MessageSend
        from .type_int import TypeInt

        originating_screen_key = self.get("_screen_key")
        if not originating_screen_key:
            raise ValueError(f"Entry {self} has no _screen_key")

        screen_id, screen_obj_id = originating_screen_key
        screen_payload: dict[str, Any] = {"screenID": screen_id}
        if screen_obj_id is not None:
            screen_payload["objID"] = screen_obj_id

        return MessageSend(
            type_int=TypeInt.ACTUAL_SCREEN,
            mc=connection.new_message_reference(),
            payload=screen_payload,
        )

    def message_action_selected(self, connection: Any) -> "MessageSend":
        """Create a message to trigger ACTION_SELECTED for this entry.

        Args:
            connection: The connection object to get message reference from.

        Returns:
            A MessageSend object for the ACTION_SELECTED message.
        """
        from .message import MessageSend
        from .type_int import TypeInt

        vid = self["VID"]
        detail = self["detail"]
        objid = self.get("objID")

        payload: dict[str, Any] = {"VID": vid, "detail": detail}
        if objid is not None:
            payload["objID"] = objid

        return MessageSend(
            type_int=TypeInt.ACTION_SELECTED,
            mc=connection.new_message_reference(),
            payload=payload,
        )


class Entries:
    def __init__(self, data):
        self._entries = {}
        self.data = data

    def validate_keys(self, data, allowed_keys, context):
        if self.data.connection.strict:
            extra_keys = set(data.keys()) - allowed_keys
            if extra_keys:
                extra_fields = {k: data[k] for k in extra_keys}
                logger.error(
                    "Strict mode: %s contains unexpected fields %s; full payload: %s",
                    context,
                    extra_keys,
                    data,
                )
                raise ValueError(
                    f"{context} contains unexpected fields: {extra_fields}"
                )

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
            if self.data.connection.strict and _vid_obj.get("type") not in (23, 4):
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
        await self.data.connection.async_notify_update(key, entry, new)

    async def update_entry(self, key, updated_entry):
        if key == (0, 0, None):
            return
        entry = self.get_entry(key)
        if entry is None:
            raise ValueError(f"update_entry() Entry {key} does not exist")

        vid = key[0]
        vid_info = self.data.dbentries[vid]
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

        await self.data.connection.async_notify_update(key, entry, False)


class Data:
    def __init__(self, connection):
        self.connection = connection
        self.dbentries = {}
        self.entries = Entries(self)
        self.screens = {}

        self.alerts = []

    async def recv_SET_HOME_DATA(self, message):
        payload = message.payload

        allowed_keys = {"id", "name", "isvalid", "info"}
        self.entries.validate_keys(payload, allowed_keys, "SET_HOME_DATA payload")

        self.connection.device_home_id = payload.get("id")
        self.connection.device_home_name = payload.get("name")
        logger.info(
            f"Received SET_HOME_DATA [301]. Payload size: {len(str(message.payload))}"
        )

        await self.connection.send_ack_message(message)

    async def recv_APP_INFO(self, message):
        payload = message.payload
        self.entries.validate_keys(payload, {"info"}, "APP_INFO payload")
        logger.info(
            f"Received APP_INFO [295]. Payload size: {len(str(message.payload))}"
        )
        await self.connection.send_ack_message(message)

    async def recv_ADD_SCREEN(self, message):
        logger.info(
            f"Received ADD_SCREEN [296]. Payload size: {len(str(message.payload))}"
        )

        payload = message.payload
        self.entries.validate_keys(payload, {"screen"}, "ADD_SCREEN payload")

        if "screen" not in payload:
            raise ValueError("ADD_SCREEN message missing 'screen' dictionary")
        screen_data = payload["screen"]

        allowed_keys = {
            "screenID",
            "title",
            "statuspage",
            "itemCount",
            "objID",
            "iconID",
        }
        self.entries.validate_keys(screen_data, allowed_keys, "Screen dictionary")

        screen_id = screen_data.get("screenID")
        obj_id = screen_data.get("objID")
        if screen_id is not None:
            self.screens[(screen_id, obj_id)] = screen_data

        self.save_screens()

        await self.connection.send_ack_message(message)

    async def recv_ADD_DBENTRIES(self, message):
        logger.info(
            f"Received ADD_DBENTRIES [297]. Payload size: {len(str(message.payload))}"
        )

        payload = message.payload
        self.entries.validate_keys(payload, {"DBentries"}, "ADD_DBENTRIES payload")
        db_entries = payload.get("DBentries", [])

        allowed_keys = {
            "VID",
            "type",
            "text",
            "min",
            "max",
            "step",
            "elements",
            "unit",
            "pwd",
        }

        for entry in db_entries:
            self.entries.validate_keys(entry, allowed_keys, "DB entry")

            vid = entry.get("VID")
            if vid is not None:
                self.dbentries[vid] = entry
        logger.debug(f"Current dbentries count: {len(self.dbentries)}")

        if self.connection.dump_entities:
            with open("dbentries.json", "w", encoding="utf-8") as f:
                json.dump(self.dbentries, f, indent=4, ensure_ascii=False)

        await self.connection.send_ack_message(message)

    async def recv_ADD_ITEMS(self, message):
        logger.info(
            f"Received ADD_ITEMS [299]. Payload size: {len(str(message.payload))}"
        )
        payload = message.payload
        self.entries.validate_keys(
            payload,
            {
                "screenID",
                "pos",
                "items",
                "end",
                "objID",
            },
            "ADD_ITEMS payload",
        )
        screen_id = payload.get("screenID")
        obj_id = payload.get("objID")

        screen_key = (screen_id, obj_id)

        if screen_key not in self.screens:
            logger.warning(
                f"Received ADD_ITEMS for unknown screenID: {screen_id}. Initializing screen entry."
            )
            self.screens[screen_key] = {"screenID": screen_id, "objID": obj_id}

        if "items" not in self.screens[screen_key]:
            self.screens[screen_key]["items"] = []

        def fix_item(it):
            allowed_keys = {
                "VID",
                "detail",
                "name",
                "edit",
                "value",
                "validity",
                "valstr",
                "objID",
                "citems",
                "highlight",
            }
            self.entries.validate_keys(it, allowed_keys, "Item")

            vid = it.get("VID")
            if vid is not None:
                _vid_obj = self.dbentries.get(vid)
                if _vid_obj is not None:
                    it["_vid_obj"] = _vid_obj

            # Add screen key reference
            it["_screen_key"] = screen_key

            if "citems" in it and isinstance(it["citems"], list):
                it["citems"] = [fix_item(cit) for cit in it["citems"]]
            return it

        new_items = [fix_item(it) for it in payload.get("items", [])]
        await self.add_entries(new_items)
        self.screens[screen_key]["items"].extend(new_items)

        self.save_screens()

        logger.info(
            f"Updated screen {screen_id} with {len(new_items)} items. Total: {len(self.screens[screen_key].get('items', []))}"
        )
        await self.connection.send_ack_message(message)

    async def recv_SET_ALERTS(self, message):
        logger.debug(
            f"Received SET_ALERTS [302]. Payload size: {len(str(message.payload))}"
        )
        payload = message.payload
        self.entries.validate_keys(
            payload, {"restart", "alerts", "end"}, "SET_ALERTS payload"
        )

        if payload.get("restart"):
            self.alerts = []

        new_alerts = payload.get("alerts", [])
        allowed_keys = {"text", "type", "icon"}

        for alert in new_alerts:
            self.entries.validate_keys(alert, allowed_keys, "Alert")

            text = alert.get("text")
            icon = alert.get("icon")
            logger.info(f"Alert Received: {text} (Icon: {icon})")

            self.alerts.append(alert)

        await self.connection.send_ack_message(message)

    async def recv_UPDATE_ITEMS(self, message):
        logger.debug(
            f"Received UPDATE_ITEMS [300]. Payload size: {len(str(message.payload))}"
        )
        payload = message.payload
        self.entries.validate_keys(payload, {"items", "end"}, "UPDATE_ITEMS payload")
        update_items = payload.get("items", [])

        for u_item in update_items:
            key = self.entries.make_key_from_object(u_item)
            await self.entries.update_entry(key, u_item)

        self.save_entries()
        self.save_screens()

        await self.connection.send_ack_message(message)

    async def add_entries(self, items, objID=None, _top_level=True):
        for item in items:
            vid = item.get("VID")
            if vid is not None:
                _vid_obj = self.dbentries.get(vid)
                if _vid_obj is not None:
                    item["_vid_obj"] = _vid_obj

            if "detail" in item:
                if objID:
                    item["objID"] = objID
                if "citems" in item and isinstance(item["citems"], list):
                    if item["citems"][0].get("objID", None):
                        item["objID"] = item["citems"][0]["objID"]

                key = self.entries.make_key_from_object(item)
                await self.entries.create_entry(key, item)

            if "citems" in item and isinstance(item["citems"], list):
                await self.add_entries(item["citems"], objID=None, _top_level=False)

        if _top_level:
            self.save_entries()

    def save_entries(self):
        dumpable = {str(k): dict(v) for k, v in self.entries._entries.items()}
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
