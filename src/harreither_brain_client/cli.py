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
    parser.add_argument(
        "-b",
        action="store_true",
        help="Send single ACTION_SELECTED sequence variant B",
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
    """Send a fixed ACTION_SELECTED sequence (variant A) and wait for ACK/NACK."""
    logging.info("Waiting for initialization to complete...")
    await conn_obj.event_initial_setup_complete.wait()
    logging.info("Initialization complete. Sending ACTION_SELECTED sequence (A)...")

    # First message
    msg1 = MessageSend(
        type_int=TypeInt.ACTION_SELECTED,
        mc=conn_obj.new_message_reference(),
        payload={"VID": 3, "detail": 1001, "objID": 1},
    )
    entry1 = get_entry_from_payload(conn_obj, msg1.payload)
    logging.info(f"Sent first ACTION_SELECTED (A) with payload: {msg1.payload}, entry: {entry1}")
    ack1 = await conn_obj.enqueue_message_get_ack(msg1)
    logging.info(f"Received ACK for first message (A): {ack1}")

    # Second message
    msg2 = MessageSend(
        type_int=TypeInt.ACTION_SELECTED,
        mc=conn_obj.new_message_reference(),
        payload={"VID": 30003, "detail": 1, "objID": 1},
    )
    entry2 = get_entry_from_payload(conn_obj, msg2.payload)
    logging.info(f"Sent second ACTION_SELECTED (A) with payload: {msg2.payload}, entry: {entry2}")
    ack2 = await conn_obj.enqueue_message_get_ack(msg2)
    logging.info(f"Received ACK for second message (A): {ack2}")

    # Wait 3 seconds before third message
#    await asyncio.sleep(3)

    # Third message
    msg3 = MessageSend(
        type_int=TypeInt.ACTION_SELECTED,
        mc=conn_obj.new_message_reference(),
        payload={"VID": 30005, "detail": 1, "objID": 1},
    )
    entry3 = get_entry_from_payload(conn_obj, msg3.payload)
    logging.info(f"Sent third ACTION_SELECTED (A) with payload: {msg3.payload}, entry: {entry3}")
    ack3 = await conn_obj.enqueue_message_get_ack(msg3)
    logging.info(f"Received ACK for third message (A): {ack3}")


async def send_single_action_b(conn_obj: Connection) -> None:
    """Send a single ACTION_SELECTED (variant B) and wait for ACK/NACK."""
    logging.info("Waiting for initialization to complete...")
    await conn_obj.event_initial_setup_complete.wait()
    logging.info("Initialization complete. Sending single ACTION_SELECTED (B)...")

    # Single message per request: detail=1009 and objID=30121
    msg = MessageSend(
        type_int=TypeInt.ACTION_SELECTED,
        mc=conn_obj.new_message_reference(),
        payload={"VID": 3, "detail": 1009, "objID": 30123},
    )
    logging.info(f"Sending ACTION_SELECTED (B) with payload: {msg.payload}")
    ack = await conn_obj.enqueue_message_get_ack(msg)
    logging.info(f"Received ACK for ACTION_SELECTED (B): {ack}")
    

async def run_client(
    *,
    host: str,
    username: str,
    password: str,
    proxy_url: str | None,
    strict: bool,
    logfile: str | None,
    use_single_action_a: bool,
    use_single_action_b: bool,
    dump_entities: bool,
) -> None:
    # Default mode (no single action) means we traverse screens
    traverse_screens_on_init = not (use_single_action_a or use_single_action_b)
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
        if use_single_action_b:
            await asyncio.gather(
                conn_obj.messages_process(),
                send_single_action_b(conn_obj),
            )
        elif use_single_action_a:
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
            use_single_action_b=args.b,
            dump_entities=args.dumpentities,
        )
    )

if __name__ == "__main__":
    main()
