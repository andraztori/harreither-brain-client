import argparse
import asyncio
import logging
import sys

from .connection import Connection


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
    return parser


def configure_logging(verbose: bool) -> None:
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stdout,
    )


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
        )
    )


async def run_client(
    *,
    host: str,
    username: str,
    password: str,
    proxy_url: str | None,
    strict: bool,
) -> None:
    conn_obj = Connection(strict_mode=strict)
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
        await conn_obj.messages_process()

    except asyncio.CancelledError:
        logging.info("Connection task cancelled")
        raise
    except Exception as exc:  # pragma: no cover - top-level protection
        logging.error("Error during connection: %s", exc, exc_info=True)
    finally:
        await conn_obj.async_close()


if __name__ == "__main__":
    main()
