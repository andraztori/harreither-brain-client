import unittest

from harreither_brain_client.data import Data
from harreither_brain_client.message import MessageReceived
from harreither_brain_client.type_int import TypeInt


class DummyConnection:
    def __init__(self, strict: bool = False) -> None:
        self.strict = strict
        self.sent_acks = []
        self.notifications = []

    async def send_ack_message(self, message) -> None:
        self.sent_acks.append(message)

    async def async_notify_update(self, key, value_dict, new):
        self.notifications.append((key, value_dict, new))


class DataHandlerTests(unittest.IsolatedAsyncioTestCase):
    async def test_recv_add_screen_stores_screen_and_sends_ack(self):
        connection = DummyConnection(strict=True)
        data = Data(connection)
        message = MessageReceived(
            type_int=TypeInt.ADD_SCREEN,
            mc=123,
            payload={
                "screen": {
                    "screenID": 42,
                    "title": "Diagnostics",
                    "statuspage": True,
                    "itemCount": 2,
                }
            },
        )

        await data.recv_ADD_SCREEN(message)

        self.assertIn(42, data.screens)
        self.assertEqual(data.screens[42]["title"], "Diagnostics")
        self.assertEqual(data.screens[42]["itemCount"], 2)
        self.assertEqual(connection.sent_acks, [message])

    async def test_recv_app_info_sends_ack(self):
        connection = DummyConnection(strict=True)
        data = Data(connection)
        message = MessageReceived(
            type_int=TypeInt.APP_INFO,
            mc=5,
            payload={"info": "500"},
        )

        await data.recv_APP_INFO(message)

        self.assertEqual(connection.sent_acks, [message])

    async def test_recv_add_dbentries_stores_entries(self):
        connection = DummyConnection(strict=True)
        data = Data(connection)
        message = MessageReceived(
            type_int=TypeInt.ADD_DBENTRIES,
            mc=6,
            payload={
                "DBentries": [
                    {"VID": 10, "type": 15, "text": "Arhiviranje"},
                    {"VID": 127, "type": 10, "text": "Cas"},
                ]
            },
        )

        await data.recv_ADD_DBENTRIES(message)

        self.assertIn(10, data.dbentries)
        self.assertEqual(data.dbentries[10]["text"], "Arhiviranje")
        self.assertIn(127, data.dbentries)
        self.assertEqual(connection.sent_acks, [message])

    async def test_recv_set_home_data_updates_device_info(self):
        connection = DummyConnection(strict=True)
        data = Data(connection)
        message = MessageReceived(
            type_int=TypeInt.SET_HOME_DATA,
            mc=4,
            payload={
                "id": "home-1",
                "name": "Primary",
                "isvalid": True,
                "info": "506",
            },
        )

        await data.recv_SET_HOME_DATA(message)

        self.assertEqual(connection.device_home_id, "home-1")
        self.assertEqual(connection.device_home_name, "Primary")
        self.assertEqual(connection.sent_acks, [message])

    async def test_recv_add_items_creates_entries_and_sends_ack(self):
        connection = DummyConnection(strict=True)
        data = Data(connection)
        data.dbentries[500] = {"VID": 500, "type": 10, "text": "Temp"}
        message = MessageReceived(
            type_int=TypeInt.ADD_ITEMS,
            mc=7,
            payload={
                "screenID": 100,
                "pos": 0,
                "items": [
                    {
                        "VID": 500,
                        "detail": 1,
                        "name": "Temperature",
                        "edit": False,
                        "value": 21.5,
                        "validity": 0,
                        "valstr": "21.5",
                    }
                ],
                "end": False,
            },
        )

        await data.recv_ADD_ITEMS(message)

        key = (500, 1, None)
        self.assertIn(key, data.entries._entries)
        self.assertEqual(
            data.entries._entries[key]["vid_obj"], {"VID": 500, "type": 10, "text": "Temp"}
        )
        self.assertEqual(data.screens[100]["items"][0]["name"], "Temperature")
        self.assertEqual(connection.sent_acks, [message])
        self.assertEqual(connection.notifications[0][0], key)
        self.assertTrue(connection.notifications[0][2])

    async def test_recv_set_alerts_restarts_and_appends(self):
        connection = DummyConnection(strict=True)
        data = Data(connection)
        data.alerts = [{"text": "old", "type": 1, "icon": 1}]
        message = MessageReceived(
            type_int=TypeInt.SET_ALERTS,
            mc=8,
            payload={
                "restart": True,
                "alerts": [{"text": "1007", "type": 1, "icon": 1}],
                "end": True,
            },
        )

        await data.recv_SET_ALERTS(message)

        self.assertEqual(data.alerts, [{"text": "1007", "type": 1, "icon": 1}])
        self.assertEqual(connection.sent_acks, [message])

    async def test_recv_update_items_updates_existing_entries(self):
        connection = DummyConnection(strict=True)
        data = Data(connection)
        key = (116, 30121, None)
        data.entries._entries[key] = {
            "VID": 116,
            "detail": 30121,
            "value": 40.0,
            "validity": 0,
        }
        message = MessageReceived(
            type_int=TypeInt.UPDATE_ITEMS,
            mc=9,
            payload={
                "items": [
                    {
                        "VID": 116,
                        "detail": 30121,
                        "value": 41.4,
                        "validity": 0,
                    }
                ],
                "end": True,
            },
        )

        await data.recv_UPDATE_ITEMS(message)

        self.assertEqual(data.entries._entries[key]["value"], 41.4)
        self.assertEqual(connection.sent_acks, [message])
        self.assertEqual(connection.notifications[0][0], key)
        self.assertEqual(connection.notifications[0][1]["value"], 41.4)
        self.assertFalse(connection.notifications[0][2])

    async def test_add_entries_handles_citems_recursively(self):
        connection = DummyConnection(strict=True)
        data = Data(connection)
        data.dbentries.update(
            {
                50005: {"VID": 50005, "text": "Group"},
                3: {"VID": 3, "text": "System"},
                122: {"VID": 122, "text": "Mode"},
            }
        )

        items = [
            {
                "VID": 50005,
                "detail": 2,
                "citems": [
                    {"VID": 3, "detail": 1001, "objID": 1, "name": "CELOTNI SISTEM"},
                    {
                        "VID": 122,
                        "detail": 1,
                        "edit": False,
                        "value": 1,
                        "validity": 0,
                        "valstr": "Zima",
                    },
                ],
            }
        ]

        await data.add_entries(items)

        parent_key = (50005, 2, 1)
        child_key = (3, 1001, 1)
        sibling_key = (122, 1, None)

        self.assertIn(parent_key, data.entries._entries)
        self.assertIn(child_key, data.entries._entries)
        self.assertIn(sibling_key, data.entries._entries)
        self.assertEqual(
            data.entries._entries[parent_key]["vid_obj"], {"VID": 50005, "text": "Group"}
        )
        self.assertEqual(
            data.entries._entries[child_key]["vid_obj"], {"VID": 3, "text": "System"}
        )
        self.assertEqual(
            data.entries._entries[sibling_key]["vid_obj"], {"VID": 122, "text": "Mode"}
        )
        self.assertEqual(len(connection.notifications), 3)
        self.assertTrue(all(n[2] for n in connection.notifications))


if __name__ == "__main__":
    unittest.main()
