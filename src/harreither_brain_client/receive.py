import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


class ReceiveData:
    def __init__(self, connection):
        self.connection = connection

    def validate_keys(self, data, allowed_keys, context):
        if self.connection.strict:
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

    async def recv_SET_HOME_DATA(self, message):
        payload = message.payload

        allowed_keys = {"id", "name", "isvalid", "info"}
        self.validate_keys(payload, allowed_keys, "SET_HOME_DATA payload")

        self.connection.device_home_id = payload.get("id")
        self.connection.device_home_name = payload.get("name")
        logger.info(
            f"Received SET_HOME_DATA [301]. Payload size: {len(str(message.payload))}"
        )

        await self.connection.send_ack_message(message)

    async def recv_APP_INFO(self, message):
        payload = message.payload
        self.validate_keys(payload, {"info"}, "APP_INFO payload")
        logger.info(
            f"Received APP_INFO [295]. Payload size: {len(str(message.payload))}"
        )
        await self.connection.send_ack_message(message)

    async def recv_ADD_SCREEN(self, message):
        logger.info(
            f"Received ADD_SCREEN [296]. Payload size: {len(str(message.payload))}"
        )

        payload = message.payload
        self.validate_keys(payload, {"screen"}, "ADD_SCREEN payload")

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
        self.validate_keys(screen_data, allowed_keys, "Screen dictionary")

        screen_id = screen_data.get("screenID")
        obj_id = screen_data.get("objID")
        if screen_id is not None:
            self.connection.entries.screens[(screen_id, obj_id)] = screen_data

        self.connection.entries.save_screens()

        await self.connection.send_ack_message(message)

    async def recv_ADD_DBENTRIES(self, message):
        logger.info(
            f"Received ADD_DBENTRIES [297]. Payload size: {len(str(message.payload))}"
        )

        payload = message.payload
        self.validate_keys(payload, {"DBentries"}, "ADD_DBENTRIES payload")
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
            self.validate_keys(entry, allowed_keys, "DB entry")

            vid = entry.get("VID")
            if vid is not None:
                self.connection.entries.dbentries[vid] = entry

        if self.connection.dump_entities:
            with open("dbentries.json", "w", encoding="utf-8") as f:
                json.dump(self.connection.entries.dbentries, f, indent=4, ensure_ascii=False)

        await self.connection.send_ack_message(message)

    async def recv_ADD_ITEMS(self, message):
        logger.info(
            f"Received ADD_ITEMS [299]. Payload size: {len(str(message.payload))}"
        )
        payload = message.payload
        self.validate_keys(
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

        if screen_key not in self.connection.entries.screens:
            logger.warning(
                f"Received ADD_ITEMS for unknown screenID: {screen_id}. Initializing screen entry."
            )
            self.connection.entries.screens[screen_key] = {"screenID": screen_id, "objID": obj_id}

        if "items" not in self.connection.entries.screens[screen_key]:
            self.connection.entries.screens[screen_key]["items"] = []

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
            self.validate_keys(it, allowed_keys, "Item")

            vid = it.get("VID")
            if vid is not None:
                _vid_obj = self.connection.entries.dbentries.get(vid)
                if _vid_obj is not None:
                    it["_vid_obj"] = _vid_obj

            # Add screen key reference
            it["_screen_key"] = screen_key

            if "citems" in it and isinstance(it["citems"], list):
                it["citems"] = [fix_item(cit) for cit in it["citems"]]
            return it

        new_items = [fix_item(it) for it in payload.get("items", [])]
        await self.add_entries(new_items)
        self.connection.entries.screens[screen_key]["items"].extend(new_items)

        self.connection.entries.save_screens()

        logger.info(
            f"Updated screen {screen_id} with {len(new_items)} items. Total: {len(self.connection.entries.screens[screen_key].get('items', []))}"
        )
        await self.connection.send_ack_message(message)

    async def recv_SET_ALERTS(self, message):
        logger.debug(
            f"Received SET_ALERTS [302]. Payload size: {len(str(message.payload))}"
        )
        payload = message.payload
        self.validate_keys(
            payload, {"restart", "alerts", "end"}, "SET_ALERTS payload"
        )

        if payload.get("restart"):
            self.connection.entries.alerts = []

        new_alerts = payload.get("alerts", [])
        allowed_keys = {"text", "type", "icon"}

        for alert in new_alerts:
            self.validate_keys(alert, allowed_keys, "Alert")

            text = alert.get("text")
            icon = alert.get("icon")
            logger.info(f"Alert Received: {text} (Icon: {icon})")

            self.connection.entries.alerts.append(alert)

        await self.connection.send_ack_message(message)

    async def recv_UPDATE_ITEMS(self, message):
        logger.debug(
            f"Received UPDATE_ITEMS [300]. Payload size: {len(str(message.payload))}"
        )
        payload = message.payload
        self.validate_keys(payload, {"items", "end"}, "UPDATE_ITEMS payload")
        update_items = payload.get("items", [])

        for u_item in update_items:
            key = self.connection.entries.make_key_from_object(u_item)
            await self.connection.entries.update_entry(key, u_item)

        self.connection.entries.save_entries()
        self.connection.entries.save_screens()

        await self.connection.send_ack_message(message)

    async def add_entries(self, items, objID=None, _top_level=True):
        for item in items:
            vid = item.get("VID")
            if vid is not None:
                _vid_obj = self.connection.entries.dbentries.get(vid)
                if _vid_obj is not None:
                    item["_vid_obj"] = _vid_obj

            if "detail" in item:
                if objID:
                    item["objID"] = objID
                if "citems" in item and isinstance(item["citems"], list):
                    if item["citems"][0].get("objID", None):
                        item["objID"] = item["citems"][0]["objID"]

                key = self.connection.entries.make_key_from_object(item)
                await self.connection.entries.create_entry(key, item)

            if "citems" in item and isinstance(item["citems"], list):
                await self.add_entries(item["citems"], objID=None, _top_level=False)

        if _top_level:
            self.connection.entries.save_entries()
