import argparse
import asyncio
import logging
import sys

from .connection import Connection
from .message import MessageSend
from .type_int import TypeInt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Harreither Brain CLI Client")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument(
        "-p", "--proxy", action="store_true", help="Use proxy on localhost:8080"
    )
    parser.add_argument(
        "--username",
        required=True,
        help="Username for authentication",
    )
    parser.add_argument(
        "--password",
        required=True,
        help="Password for authentication",
    )
    parser.add_argument(
        "--host",
        required=True,
        help="WebSocket server URL",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on any unexpected fields from server",
    )
    parser.add_argument(
        "--logfile",
        help="If set, log raw messages to this file",
    )
    parser.add_argument(
        "--dumpentities",
        action="store_true",
        help="Dump dbentries, entries, and screens JSON files to disk",
    )
    parser.add_argument(
        "-a",
        action="store_true",
        help="Send single ACTION_SELECTED sequence variant A",
    )
    return parser


def configure_logging(verbose: bool) -> None:
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stdout,
    )
    
    # Suppress debug logging for websockets even in verbose mode
    if verbose:
        logging.getLogger("websockets.client").setLevel(logging.INFO)


def get_entry_from_payload(conn_obj: Connection, payload: dict):
    """Get entry from payload by converting to key tuple."""
    key = (payload.get("VID"), payload.get("detail"), payload.get("objID"))
    return conn_obj.data.entries.get_entry(key)


async def send_single_action_a(conn_obj: Connection) -> None:
    """Send a sequence of actions and wait for ACK/NACK."""
    logging.info("Waiting for traversal to complete...")
    await conn_obj.event_initial_traverse_screens_complete.wait()
    logging.info("Traversal complete. Sending action sequence...")
    '''
    # 1. Activate screenID: 200
    screen_msg = MessageSend(
        type_int=TypeInt.ACTUAL_SCREEN,
        mc=conn_obj.new_message_reference(),
        payload={"screenID": 200},
    )
    logging.info(f"Sending ACTUAL_SCREEN with payload: {screen_msg.payload}")
    screen_ack = await conn_obj.enqueue_message_get_ack(screen_msg)
    logging.info(f"Received ACK for screen activation: {screen_ack}")
    await asyncio.sleep(1)
    
    # 2. Send ACTION_SELECTED message for entity {'VID': 30044, 'detail': 1012}
    action_msg1 = MessageSend(
        type_int=TypeInt.ACTION_SELECTED,
        mc=conn_obj.new_message_reference(),
        payload={"VID": 30044, "detail": 1012},
    )
    logging.info(f"Sending ACTION_SELECTED with payload: {action_msg1.payload}")
    action_ack1 = await conn_obj.enqueue_message_get_ack(action_msg1)
    logging.info(f"Received ACK for ACTION_SELECTED: {action_ack1}")
    await asyncio.sleep(1)
    
    # 3. Send ACTION_SELECTED message for entity {'VID': 3, 'detail': 1013, 'objID': 30018}
    action_msg2 = MessageSend(
        type_int=TypeInt.ACTION_SELECTED,
        mc=conn_obj.new_message_reference(),
        payload={"VID": 3, "detail": 1013, "objID": 30018},
    )
    logging.info(f"Sending ACTION_SELECTED with payload: {action_msg2.payload}")
    action_ack2 = await conn_obj.enqueue_message_get_ack(action_msg2)
    logging.info(f"Received ACK for ACTION_SELECTED: {action_ack2}")
    await asyncio.sleep(1)
    
    # 4. Activate entering screen for VID: 1161, detail: 30018
    entry = conn_obj.data.entries.get_entry((1161, 30018, None))
    if not entry:
        # Try to find with any objID
        for key, e in conn_obj.data.entries._entries.items():
            if key[0] == 1161 and key[1] == 30018:
                entry = e
                break
        if not entry:
            raise ValueError("Entry with VID=1161, detail=30018 not found after traversal")
    
    '''

    entry = conn_obj.data.entries.get_entry((1161, 30018, None))
    '''
    screen_msg = entry.message_activate_entering_screen(conn_obj)
    logging.info(f"Sending message_activate_entering_screen with payload: {screen_msg.payload}")
    screen_ack = await conn_obj.enqueue_message_get_ack(screen_msg)
    logging.info(f"Received ACK: {screen_ack}")
    '''

    msg = entry.message_edit_value(0, conn_obj)
    logging.info(f"Sending message_edit_value with payload: {msg.payload}")
    ack = await conn_obj.enqueue_message_get_ack(msg)
    logging.info(f"Received ACK: {ack}")
    await asyncio.sleep(1)
  


async def run_client(
    *,
    host: str,
    username: str,
    password: str,
    proxy_url: str | None,
    strict: bool,
    logfile: str | None,
    use_single_action_a: bool,
    dump_entities: bool,
) -> None:
    # Default mode (no single action) means we traverse screens
    traverse_screens_on_init = True
    conn_obj = Connection(
        strict_mode=strict,
        message_log_filename=logfile,
        dump_entities=dump_entities,
        traverse_screens_on_init=traverse_screens_on_init,
    )
    
    try:
        await conn_obj.async_websocket_connect(host, proxy_url=proxy_url)
        logging.info("Connected to WS server")

        await conn_obj.establish_secure_connection()
        await conn_obj.enqueue_authentication_flow(
            username=username,
            password=password,
            auto_start_session=True,
            async_auth_result_callback=None,
        )
        
        # Run messages_process and either send a single-action variant or request type 1 entries
        if use_single_action_a:
            await asyncio.gather(
                conn_obj.messages_process(),
                send_single_action_a(conn_obj),
            )
        else:
            await asyncio.gather(
                conn_obj.messages_process(),
            )

    except asyncio.CancelledError:
        logging.info("Connection task cancelled")
        raise
    except Exception as exc:  # pragma: no cover - top-level protection
        logging.error("Error during connection: %s", exc, exc_info=True)
    finally:
        await conn_obj.async_close()


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(args=argv)

    configure_logging(args.verbose)

    proxy_url = "http://localhost:8080" if args.proxy else None

    asyncio.run(
        run_client(
            host=args.host,
            username=args.username,
            password=args.password,
            proxy_url=proxy_url,
            strict=args.strict,
            logfile=args.logfile,
            use_single_action_a=args.a,
            dump_entities=args.dumpentities,
        )
    )

if __name__ == "__main__":
    main()
